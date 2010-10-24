/* Getting a stacktrace from a remote process. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

void
do_the_backtrace(unw_cursor_t *cursor)
{
  while (unw_step(cursor) > 0)
  {
    unw_word_t ip, sp;
    unw_word_t offp;
    char buf[1024];
    strcpy(buf, "");
    unw_get_proc_name(cursor, buf, sizeof(buf), &offp);
    unw_get_reg(cursor, UNW_REG_IP, &ip);
    unw_get_reg(cursor, UNW_REG_SP, &sp);
    printf("ip = %lx, sp = %lx <%s>+%d\n", (long) ip, (long) sp, buf, (long)offp);
  }
}

int
main(int argc, char *argv[])
{
  int pid= 0;
  long perr;
  int wait_status;
  int err;
  unw_addr_space_t addr_space= 0;
  void *upt_info= NULL;
  unw_cursor_t cursor;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    exit(1);
  }

  pid= atoi(argv[1]);

  perr= ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (perr)
  {
    perror("ptrace(PTRACE_ATTACH) failed");
    exit(1);
  }
  err= waitpid(pid, &wait_status, 0);
  if (err == -1)
  {
    perror("waitpid()");
    exit(1);
  }

  addr_space= unw_create_addr_space(&_UPT_accessors, 0);
  if (!addr_space)
  {
    fprintf(stderr, "Error: unw_create_addr_space() failed.\n");
    goto err_exit;
  }
  upt_info= _UPT_create(pid);
  if (!upt_info)
  {
    fprintf(stderr, "Error: _UPT_create() failed.\n");
    goto err_exit;
  }
  err= unw_init_remote(&cursor, addr_space, upt_info);
  if (err)
  {
    fprintf(stderr, "Error: unw_init_remote() returned %d\n", err);
    goto err_exit;
  }

  do_the_backtrace(&cursor);

err_exit:
  if (upt_info)
    _UPT_destroy(upt_info);
  if (addr_space)
    unw_destroy_addr_space(addr_space);

  if (pid)
  {
    perr= ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if (perr)
      fprintf(stderr, "Warning: ptrace(PTRACE_DETACH, %d) returned error: %d\n",
              (int)pid, errno);
  }

  return 0;
}
