/* Getting a stacktrace from a remote process. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <set>
#include <map>
#include <vector>
using namespace std;

#include <libunwind.h>
#include <libunwind-ptrace.h>

#define READ_PAGE_SIZE 4096
#define READ_PAGE_SIZE_MASK ~((unw_word_t)4096-1)

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
  seen_tids.clear();
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
    for (set<int>::iterator it= new_tids.begin(); it != new_tids.end(); ++it)
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
    for (set<int>::iterator it= new_tids.begin(); it != new_tids.end(); ++it)
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
  for (set<int>::iterator it= seen_tids.begin(); it != seen_tids.end(); ++it)
  {
    long perr= ptrace(PTRACE_DETACH, *it, NULL, NULL);
    if (perr)
      fprintf(stderr, "Warning: ptrace(PTRACE_DETACH, %d) returned error: %d\n",
              *it, errno);
  }
}

static vector<unw_word_t> backtrace;
static void
do_the_backtrace(int pid, unw_addr_space_t addr_space, void *upt_info)
{
  int err;

  unw_cursor_t cursor;
  err= unw_init_remote(&cursor, addr_space, upt_info);
  if (err)
  {
    fprintf(stderr, "Error: unw_init_remote() returned %d\n", err);
    return;
  }

  backtrace.clear();
  do
  {
    unw_word_t ip= 0;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    backtrace.push_back(ip);
  } while (unw_step(&cursor) > 0);

  for (vector<unw_word_t>::iterator it= backtrace.begin();
       it != backtrace.end();
       ++it)
  {
    char buf[1024];
    unw_word_t offp= 0;
    strcpy(buf, "");    /* So we just print empty on error */
    _UPT_get_proc_name(addr_space, *it, buf, sizeof(buf), &offp, upt_info);
    printf("ip = %lx <%s>+%d\n", (long) *it, buf, (long)offp);
  }
}

/*
  Read and parse /proc/<pid>/maps to find any read-only maps.
  For such maps, we can cache reads across multiple stacktraces.
  Errors here are non-fatal; we will just be unable to cache
  read-only maps.
*/
struct read_only_map { unsigned long start, end; };
static vector<read_only_map> read_only_maps;
static void
find_readonly_maps(int pid)
{
  char buf[32];
  sprintf(buf, "/proc/%d/maps", pid);
  FILE *f = fopen(buf, "r");
  if (!f)
  {
    fprintf(stderr, "Warning: unable to open %s: %d: %s\n",
            errno, strerror(errno));
    return;
  }
  for (;;)
  {
    struct read_only_map entry;
    char perms[5];
    int res = fscanf(f, "%lx-%lx %4[rwxsp-] %*[^\n]",
                     &entry.start, &entry.end, perms);
    if (res != 3)
      break;
    if (perms[0] != '\0' && perms[1] == '-')
    {
      /* A read-only map. */
      //fprintf(stderr, "Found read-only map: 0x%lx - 0x%lx\n", entry.start, entry.end);
      read_only_maps.push_back(entry);
    }
  }
  fclose(f);
}

static int (*orig_access_mem)(unw_addr_space_t, unw_word_t, unw_word_t *,
                              int, void *);
/*
  The default ptrace-based access_mem callback in libunwind just invokes
  ptrace(PTRACE_PEEKDATA, ...). We can save a lot of system calls just by
  caching repeated reads.
  Additionally, rather than using ptrace, we read a whole page at a time
  from /proc/<pid>/mem, thus allowing to get more values with a single
  syscall; this should save some time also as long as reads tend to be
  somewhat clustered.
*/
static map<unw_word_t, unsigned char *> cached_reads;
static int proc_pid_mem_fd = -1;

static int
my_access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *valp,
              int write, void *arg)
{
  if (write)
    return (*orig_access_mem)(as, addr, valp, write, arg);

  unw_word_t base_addr= addr & READ_PAGE_SIZE_MASK;
  const map<unw_word_t, unsigned char *>::iterator it=
    cached_reads.find(base_addr);
  if (it != cached_reads.end())
  {
    /* Found! */
    memcpy(valp, it->second+(addr-base_addr), sizeof(*valp));
    //fprintf(stderr, "my_access_mem() CACHED 0x%lx -> 0x%lx\n", addr, valp);
    return 0;
  }

  unsigned char *page = new unsigned char[READ_PAGE_SIZE];
  if (!page)
    return UNW_ENOMEM;
  ssize_t res = pread(proc_pid_mem_fd, page, READ_PAGE_SIZE, base_addr);
  if (res != READ_PAGE_SIZE)
  {
    if (res < 0)
      fprintf(stderr, "Error reading from target process memory: %d: %s\n",
              errno, strerror(errno));
    else
      fprintf(stderr, "Short read reading from target process memory: "
              "asked for %u bytes but got %u\n", READ_PAGE_SIZE,
              (unsigned)res);
    delete[] page;
    return UNW_EUNSPEC;
  }

  cached_reads.insert(pair<unw_word_t, unsigned char *>(base_addr, page));
  memcpy(valp, page+(addr-base_addr), sizeof(*valp));
  //fprintf(stderr, "my_access_mem() NEW 0x%lx -> 0x%lx\n", addr, valp);
  return 0;
}

static void
clear_non_read_only_maps()
{
  for (map<unw_word_t, unsigned char *>::iterator it= cached_reads.begin();
       it != cached_reads.end();
       )
  {
    unw_word_t base_addr= it->first;
    bool read_only= false;
    for (vector<read_only_map>::iterator it2= read_only_maps.begin();
         it2 != read_only_maps.end();
         ++it2)
    {
      if (it2->start <= base_addr && base_addr < it2->end)
      {
        read_only= true;
        break;
      }
    }
    if (!read_only)
    {
      /* It was not a read-only map, so delete it. */
      //fprintf(stderr, "Deleting non-read-only cached block %lx\n", it->first);
      delete [] it->second;
      cached_reads.erase(it++);
    }
    else
    {
      //fprintf(stderr, "Keeping read-only cached block %lx\n", it->first);
      ++it;
    }
  }
}

static void
clear_all_maps()
{
  for (map<unw_word_t, unsigned char *>::iterator it= cached_reads.begin();
       it != cached_reads.end();
       cached_reads.erase(it++))
  {
    delete [] it->second;
  }
}

int
main(int argc, char *argv[])
{
  unw_addr_space_t addr_space= NULL;
  int pid, err;
  unw_accessors_t my_accessors;
  void *upt_info= NULL;

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
  char buf[30];
  sprintf(buf, "/proc/%d/mem", pid);
  proc_pid_mem_fd = open(buf, O_RDONLY, 0);
  if (proc_pid_mem_fd < 0)
  {
    fprintf(stderr, "Failed to open %s: %d: %s\n", buf, errno, strerror(errno));
    goto err_exit;
  }

  find_readonly_maps(pid);

  upt_info= _UPT_create(pid);
  if (!upt_info)
  {
    fprintf(stderr, "_UPT_create(%d) failed.\n", pid);
    goto err_exit;
  }

  err= ptrace_all_threads(pid);
  if (!err)
  {
    for (set<int>::iterator it= seen_tids.begin();
         it != seen_tids.end();
         ++it)
    {
      printf("\nThread: %d\n", *it);
      do_the_backtrace(*it, addr_space, upt_info);
    }
  }
  puntrace_all();

  clear_non_read_only_maps();

err_exit:
  if (upt_info)
    _UPT_destroy(upt_info);
  clear_all_maps();
  if (proc_pid_mem_fd >= 0)
    close(proc_pid_mem_fd);
  if (addr_space)
    unw_destroy_addr_space(addr_space);

  return 0;
}
