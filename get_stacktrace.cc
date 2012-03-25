/* Getting a stacktrace from a remote process. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <set>
#include <map>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

#include <libunwind.h>
#include <libunwind-ptrace.h>

#define MAX_FRAMES 20

#define READ_PAGE_SIZE 4096
#define READ_PAGE_SIZE_MASK ~((unw_word_t)4096-1)


static int cached_mem_read(unw_word_t addr, unw_word_t *valp);


static int probe_freq= 1;
static int probe_max= 1;
static enum {
  BACK_LIBUNWIND, BACK_FRAME_POINTER
} backtrace_method= BACK_LIBUNWIND;


static double
get_current_time()
{
  struct timespec t;
  int res= clock_gettime(CLOCK_REALTIME, &t);
  if (res)
  {
    fprintf(stderr, "Error: clock_gettime() failed: %d: %s\n",
            errno, strerror(errno));
    exit(1);
  }
  return (double)t.tv_sec + 1e-9*(double)t.tv_nsec;
}


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

static void
do_the_backtrace(unw_addr_space_t addr_space, void *upt_info,
                 vector<unw_word_t> *backtrace, int limit)
{
  int err;

  unw_cursor_t cursor;
  err= unw_init_remote(&cursor, addr_space, upt_info);
  if (err)
  {
    fprintf(stderr, "Error: unw_init_remote() returned %d\n", err);
    return;
  }

  backtrace->clear();
  do
  {
    unw_word_t ip= 0;
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    backtrace->push_back(ip);
  } while (--limit > 0 && unw_step(&cursor) > 0);
}


/*
  If we have -fno-omit-frame-pointer, we can obtain a backtrace simply
  by walking the frame pointer chain.
*/
static void
frame_pointer_backtrace(pid_t thread, vector<unw_word_t> *backtrace, int limit)
{
  /*
    When using frame pointer, %rbp always points to the current stack frame.
    More precisely, %rbp points to the location where old frame pointer is
    stored, and (%rbp+8) holds the return address.

    So to unwind the stack, we first obtain %rip and %rbp using ptrace - and
    %rip is then the start of the backtrace. Then we loop, loading (%rbp)
    and (%rbp+8) to get new values of %rbp and %rip.
  */

  backtrace->clear();
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, thread, 0, &regs))
  {
    fprintf(stderr, "Warning: Failed to read regs from thread: %d: %s\n",
            errno, strerror(errno));
    return;
  }

  unw_word_t rip= regs.rip;
  unw_word_t rbp= regs.rbp;
  for (;;)
  {
    backtrace->push_back(rip);
    if (!rbp || --limit <- 0)
      break;
    unw_word_t new_rbp, new_rip;
    if (cached_mem_read(rbp, &new_rbp) ||
        cached_mem_read(rbp+sizeof(unw_word_t), &new_rip))
    {
      /*
        We can't read from the supposed stack frame - so we probably
        reached the end (or maybe we got off track somehow).
      */
      break;
    }
    rbp= new_rbp;
    rip= new_rip;
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
  return cached_mem_read(addr, valp);
}

static int
cached_mem_read(unw_word_t addr, unw_word_t *valp)
{
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
    {
/*
      fprintf(stderr,
              "Error reading from target process memory %p: %d: %s\n",
              page, errno, strerror(errno));
*/
    }
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

static struct my_stack_compare {
  typedef pair<string, int> T;
  bool operator() (T i, T j)
  {
    return i.second < j.second || (i.second == j.second && i.first < j.first);
  }
} my_stack_comparer;

struct thread_info {
  void * upt_info;
  vector<unw_word_t> backtrace;
};
static map<int, thread_info> thread_infos;
struct symbol_info {
  string name;
  unw_word_t offp;
};
static map<unw_word_t, symbol_info> symbol_infos;

static map<string, int> trace_map;
int
main(int argc, char *argv[])
{
  unw_addr_space_t addr_space= NULL;
  int pid, err;
  unw_accessors_t my_accessors;
  void *upt_info= NULL;
  struct thread_info new_entry;
  double start_time= get_current_time(), suspend_time=0;
  int total_backtraces= 0;

  char **p= &argv[1];
  while (argc > 2)
  {
    if (0 == strcmp(*p, "--framepointer"))
      backtrace_method= BACK_FRAME_POINTER;
    else if (0 == strcmp(*p, "--libunwind"))
      backtrace_method= BACK_LIBUNWIND;
    else if (0 == strncmp(*p, "--freq=", 7))
    {
      probe_freq= atoi(&(*p)[7]);
      if (probe_freq <= 0)
      {
        fprintf(stderr, "Error: --freq must be a number > 0\n");
        exit(1);
      }
    }
    else if (0 == strncmp(*p, "--max=", 6))
      probe_max= atoi(&(*p)[6]);
    else
      break;
    ++p;
    --argc;
  }
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s [--libunwind | --framepointer] "
            "[--max=N] [--freq=N] <pid>\n",
            argv[0]);
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

  pid= atoi(*p);
  char buf[30];
  sprintf(buf, "/proc/%d/mem", pid);
  proc_pid_mem_fd = open(buf, O_RDONLY, 0);
  if (proc_pid_mem_fd < 0)
  {
    fprintf(stderr, "Failed to open %s: %d: %s\n", buf, errno, strerror(errno));
    goto err_exit;
  }

  find_readonly_maps(pid);

  for (int i= 0; probe_max == 0 || i < probe_max; ++i)
  {
    map<int, thread_info> prev_infos= thread_infos;
    thread_infos.clear();

    /*
      Now ptrace() all threads of the target process, and obtain a backtrace
      from each of them.
      Do the minimum necessary here, to stall the target process as little as
      possible, and defer as much as possible to afterwards.
    */

    double cur_time= get_current_time();
    err= ptrace_all_threads(pid);
    if (err)
    {
      puntrace_all();
      goto err_exit;
    }
    for (set<int>::iterator it= seen_tids.begin();
         it != seen_tids.end();
         ++it)
    {
      int pid= *it;

      map<int, thread_info>::iterator thr;
      const map<int, thread_info>::iterator old= prev_infos.find(pid);
      if (old == prev_infos.end())
      {
        /* First time thread seen - create a new entry. */
        thr= thread_infos.insert(pair<int, thread_info>(pid, new_entry)).first;
        thr->second.upt_info= _UPT_create(pid);
        if (!thr->second.upt_info)
        {
          fprintf(stderr, "_UPT_create(%d) failed.\n", pid);
          puntrace_all();
          goto err_exit;
        }
      }
      else
      {
        /* Re-use the old entry for this thread. */
        thr= thread_infos.insert(pair<int, thread_info>(pid, old->second)).first;
        prev_infos.erase(old);
      }
      switch (backtrace_method)
      {
      case BACK_LIBUNWIND:
        do_the_backtrace(addr_space, thr->second.upt_info,
                         &thr->second.backtrace, MAX_FRAMES);
        break;
      case BACK_FRAME_POINTER:
        frame_pointer_backtrace(pid, &thr->second.backtrace, MAX_FRAMES);
        break;
      default:
        abort();
      }
    }

    puntrace_all();
    suspend_time+= get_current_time() - cur_time;

    /* Now target process is release; do rest of processing. */

    /* Free info for any threads no longer present. */
    for (map<int, thread_info>::iterator it= prev_infos.begin();
         it != prev_infos.end();
         ++it)
    {
      _UPT_destroy(it->second.upt_info);
    }
    prev_infos.clear();

    /* Now resolve symbols and print each backtrace. */
    for (map<int, thread_info>::iterator it= thread_infos.begin();
         it != thread_infos.end();
         ++it)
    {
      if (probe_max == 1)
        printf("\nThread: %d\n", it->first);
      string key;
      int sep= 0;
      for (vector<unw_word_t>::iterator frame= it->second.backtrace.begin();
           frame != it->second.backtrace.end();
           ++frame)
      {
        map<unw_word_t, symbol_info>::iterator sym;
        sym = symbol_infos.find(*frame);
        if (sym == symbol_infos.end())
        {
          char buf[1024];
          struct symbol_info info;
          strcpy(buf, "??");
          _UPT_get_proc_name(addr_space, *frame, buf, sizeof(buf), &info.offp,
                             it->second.upt_info);
          info.name= buf;
          sym= symbol_infos.insert
            (pair<unw_word_t, symbol_info>(*frame, info)).first;
        }

        if (probe_max == 1)
          printf("ip = %lx <%s>+%d\n", (long) *frame, sym->second.name.c_str(),
                 (unsigned long)sym->second.offp);
        else
        {
          if (sep)
            key+= ":";
          key+= sym->second.name;
          sep= 1;
        }
      }
      ++(trace_map.insert(pair<string,int>(key, 0)).first->second);
      ++total_backtraces;
    }

    /*
      Drop from cache any reads from non-read-only maps, as they may well
      change before the next stack traces.
    */
    clear_non_read_only_maps();

    if ((i + 1) % probe_freq == 0)
    {
      vector< pair<string, int> > list(trace_map.begin(), trace_map.end());
      std::sort(list.begin(), list.end(), my_stack_comparer);
      printf("\n\n");
      int total= list.size();
      for (vector<pair<string, int> >::iterator it= list.begin();
           it != list.end();
           ++it)
      {
        if (--total < 20)
            printf("  %5d  %5.2f%%  %s\n", it->second,
                   (double)it->second/(double)total_backtraces*100,
                   it->first.c_str());
      }

      double total_time= get_current_time() - start_time;
      printf("Target process suspended %5.2f%% of %.2f seconds\n",
             suspend_time/total_time*100, total_time);
    }

    if (i + 1 == probe_max)
      break;

    /* Sleep a short while until next probe. */
    struct timespec req, rem;
    if (probe_freq <= 1)
    {
      req.tv_sec= 1;
      req.tv_nsec= 0;
    }
    else
    {
      req.tv_sec= 0;
      req.tv_nsec= (long)1000000000/(long)probe_freq;
    }
    for (;;)
    {
      if (0 == nanosleep(&req, &rem))
        break;
      req= rem;
    }
  }

err_exit:
  for (map<int, thread_info>::iterator it= thread_infos.begin();
       it != thread_infos.end();
       ++it)
  {
    _UPT_destroy(it->second.upt_info);
  }
  thread_infos.clear();
  clear_all_maps();
  if (proc_pid_mem_fd >= 0)
    close(proc_pid_mem_fd);
  if (addr_space)
    unw_destroy_addr_space(addr_space);

  return 0;
}
