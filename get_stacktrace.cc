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
#include <map>
using namespace std;

#include <libunwind.h>
#include <libunwind-ptrace.h>

static set<int> seen_tids;

static int
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

static void
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

static void
do_the_backtrace(int pid, unw_addr_space_t addr_space)
{
  void *upt_info= NULL;
  int err;

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
    unw_word_t ip= 0;
    unw_word_t offp= 0;
    char buf[1024];
    strcpy(buf, "");
//     unw_get_proc_name(&cursor, buf, sizeof(buf), &offp);
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    printf("ip = %lx <%s>+%d\n", (long) ip, buf, (long)offp);
  } while (unw_step(&cursor) > 0);

err_exit:
  if (upt_info)
    _UPT_destroy(upt_info);
}

static int (*orig_access_mem)(unw_addr_space_t, unw_word_t, unw_word_t *,
                              int, void *);
/*
  The default ptrace-based access_mem callback in libunwind just invokes
  ptrace(PTRACE_PEEKDATA, ...). We can save a lot of system calls just by
  caching repeated reads.
*/
static map<unw_word_t, unw_word_t> cached_reads;

static int
my_access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *valp,
              int write, void *arg)
{
  if (!write)
  {
    const map<unw_word_t, unw_word_t>::iterator it= cached_reads.find(addr);
    if (it != cached_reads.end())
    {
      *valp= it->second;
      return 0;
    }
    else
    {
      int err= (*orig_access_mem)(as, addr, valp, write, arg);
      if (!err)
        cached_reads.insert(pair<unw_word_t, unw_word_t>(addr,*valp));
      return err;
    }
  }

  return (*orig_access_mem)(as, addr, valp, write, arg);
}

int
main(int argc, char *argv[])
{
  unw_addr_space_t addr_space= NULL;
  int pid, err;
  unw_accessors_t my_accessors;

  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    exit(1);
  }

  memcpy(&my_accessors, &_UPT_accessors, sizeof(my_accessors));
  orig_access_mem= my_accessors.access_mem;
  my_accessors.access_mem= my_access_mem;
  addr_space= unw_create_addr_space(&my_accessors, 0);
  if (!addr_space)
  {
    fprintf(stderr, "unw_create_addr_space() failed.\n");
    goto err_exit;
  }

  pid= atoi(argv[1]);

  err= ptrace_all_threads(pid);
  if (!err)
  {
    for (set<int>::iterator it= seen_tids.begin(); it != seen_tids.end(); it++)
    {
      printf("\nThread: %d\n", *it);
      do_the_backtrace(*it, addr_space);
    }
  }

  puntrace_all();

err_exit:
  if (addr_space)
    unw_destroy_addr_space(addr_space);

  return 0;
}
