/* Getting a stacktrace from a remote process. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

#include <set>
using namespace std;

#include <libunwind.h>
#include <libunwind-ptrace.h>

set<int> seen_tids;

int
ptrace_all_threads(int pid)
{
  DIR *dir= NULL;
  int ret= 1;
  char buf[100];

  sprintf(buf, "/proc/%d/task", pid);

  /*
    Loop repeated over /proc/<pid>/task/, ptrace()'ing all threads found.
    Ptrace them as close together as possible, hoping to get all at once,
    however loop again if they manage to spawn a new one in-between, and
    we will eventually get them all.
  */
  for (;;)
  {
    dir= opendir(buf);
    if (!dir)
    {
      perror("Error in readdir()");
      goto err_exit;
    }

    set<int> new_tids;
    for (;;)
    {
      struct dirent *entry= readdir(dir);
      if (!entry)
        break;
      int thr_id= atoi(entry->d_name);
      if (!thr_id)
        continue;
      if (seen_tids.count(thr_id))
        continue;
      new_tids.insert(thr_id);
    }
    closedir(dir);
    dir= NULL;

    if (new_tids.empty())
      break;

    /* Now ptrace all the threads found... */
    for (set<int>::iterator it= new_tids.begin(); it != new_tids.end(); it++)
    {
      long perr= ptrace(PTRACE_ATTACH, *it, NULL, NULL);
      if (perr)
      {
        if (errno == ESRCH)
        {
          /* Thread managed to exit before we could ptrace it, so ignore. */
        }
        else
        {
          fprintf(stderr, "Error: ptrace(PTRACE_ATTACH, %d) failed: %d\n", *it, errno);
          goto err_exit;
        }
      }
      seen_tids.insert(*it);
    }

    /* ... and wait for them to stop. */
    for (set<int>::iterator it= new_tids.begin(); it != new_tids.end(); it++)
    {
      if (!seen_tids.count(*it))
        continue;                     /* Exited before we could ptrace() it */

      /*
        The __WALL linux-specific option is necessary, otherwise waiting for
        NPTL threads on the parent ptrace()d process return ECHILD.
      */
      pid_t err= waitpid(*it, NULL, __WALL);
      if (err == (pid_t)-1)
      {
        fprintf(stderr, "Error: waitpid(%d) failed: %d\n", *it, errno);
        goto err_exit;
      }
    }
  }

  ret= 0;

err_exit:
  if (dir)
    closedir(dir);

  return ret;
}

void
puntrace_all()
{
  for (set<int>::iterator it= seen_tids.begin(); it != seen_tids.end(); it++)
  {
    long perr= ptrace(PTRACE_DETACH, *it, NULL, NULL);
    if (perr)
      fprintf(stderr, "Warning: ptrace(PTRACE_DETACH, %d) returned error: %d\n",
              *it, errno);
  }
}

void
do_the_backtrace(int pid)
{
  unw_addr_space_t addr_space= NULL;
  void *upt_info= NULL;
  int err;

  addr_space= unw_create_addr_space(&_UPT_accessors, 0);
  if (!addr_space)
  {
    fprintf(stderr, "unw_create_addr_space() failed.\n");
    goto err_exit;
  }
  upt_info= _UPT_create(pid);
  if (!upt_info)
  {
    fprintf(stderr, "_UPT_create(%d) failed.\n", pid);
    goto err_exit;
  }
  unw_cursor_t cursor;
  err= unw_init_remote(&cursor, addr_space, upt_info);
  if (err)
  {
    fprintf(stderr, "Error: unw_init_remote() returned %d\n", err);
    goto err_exit;
  }

  do
  {
    unw_word_t ip, sp;
    unw_word_t offp;
    char buf[1024];
    strcpy(buf, "");
    unw_get_proc_name(&cursor, buf, sizeof(buf), &offp);
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);
    printf("ip = %lx, sp = %lx <%s>+%d\n", (long) ip, (long) sp, buf, (long)offp);
  } while (unw_step(&cursor) > 0);

err_exit:
  if (upt_info)
    _UPT_destroy(upt_info);
  if (addr_space)
    unw_destroy_addr_space(addr_space);
}

int
main(int argc, char *argv[])
{
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    exit(1);
  }

  int pid= atoi(argv[1]);

  int err= ptrace_all_threads(pid);
  if (!err)
  {
    for (set<int>::iterator it= seen_tids.begin(); it != seen_tids.end(); it++)
    {
      printf("\nThread: %d\n", *it);
      do_the_backtrace(*it);
    }
  }

  puntrace_all();

  return 0;
}