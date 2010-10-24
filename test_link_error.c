#include <stdio.h>

int
main(int argc, char *argv[])
{
  extern void *_UPT_create(int);
  printf("Address of _UPT_create is %p\n", _UPT_create);
  return 0;
}
