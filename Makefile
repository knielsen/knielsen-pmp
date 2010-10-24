.PHONY: all

all: test1 test_proc_mem get_stacktrace

get_stacktrace: get_stacktrace.c
	gcc -Iinclude -o $@ $< -Llib -lunwind-ptrace -lunwind-generic

test1: test1.c
	gcc -Iinclude -O3 -fno-omit-frame-pointer -o $@ $< -Llib -lunwind

test_proc_mem: test_proc_mem.c
	gcc -o $@ $<
