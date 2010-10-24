/* Simple test, takes from libunwind docs. */

#include <stdio.h>
#include <string.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

static void show_backtrace (void) {
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp;

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    unw_word_t offp;
    char buf[1024];
    strcpy(buf, "");
    unw_get_proc_name(&cursor, buf, sizeof(buf), &offp);
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);
    printf ("ip = %lx, sp = %lx <%s>+%d\n", (long) ip, (long) sp, buf, (long)offp);
  }
}

static void
func(int x)
{
  if (x)
    func(x - 1);
  else
    show_backtrace();
}

int
main(int argc, char *argv[])
{
  func(argc);
  return 0;
}
