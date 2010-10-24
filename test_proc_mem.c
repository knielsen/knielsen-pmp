/*
  Check if we can use /proc/<PID>/mem

  Conclusion: reading works fine. Writing fails with EINVAL.

  Seems that writing is disabled in Linux kernel sources fs/proc/base.c due to
  security issues (#define mem_write NULL).

      http://lkml.org/lkml/2006/3/10/224
*/

#define _XOPEN_SOURCE 500
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

int
main(int argc, char *argv[])
{
  off_t off;
  int fd;
  char buf[1024];
  char buf2[1024];
  ssize_t act;
  char *p;

  sprintf(buf, "/proc/%d/mem", getpid());
  fd= open(buf, O_RDWR|O_LARGEFILE);
  if (fd < 0)
  {
    perror("open()");
    exit(1);
  }
  sprintf(buf, "Hi, I am process %d", getpid());
  printf("Original: %s\n", buf);
  act= pread(fd, buf2, strlen(buf)+1, (off_t)buf);
  if (act == (ssize_t)-1)
  {
    perror("read()");
    exit(1);
  }
  printf("Read from /dev/%d/mem: %s\n", getpid(), buf2);
  for (p= buf2; *p; p++)
    *p= toupper(*p);
  act= pwrite(fd, buf2, strlen(buf2)+1, (off_t)buf);
  if (act == (ssize_t)-1)
  {
    perror("write()");
    exit(1);
  }
  printf("Updated via /dev/%d/mem: %s\n", getpid(), buf);

  return 0;
}
