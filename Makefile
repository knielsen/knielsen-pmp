.PHONY: all

all: test1 test_proc_mem get_stacktrace get_stacktrace-static

get_stacktrace: get_stacktrace.cc
	g++ -g -O3 -fomit-frame-pointer -o $@ $< -Llib -lunwind-ptrace -lunwind-generic -lrt

get_stacktrace-static: get_stacktrace.cc
	g++ -g -O3 -fomit-frame-pointer -o $@ -static $< -Llib -lunwind-ptrace -lunwind-generic -lunwind -lrt

test1: test1.c
	gcc -Iinclude -O3 -fno-omit-frame-pointer -o $@ $< -Llib -lunwind

test_proc_mem: test_proc_mem.c
	gcc -o $@ $<
