.PHONY: all
.PHONY: clean

CFLAGS=-g3 -Wall -Wextra -Og -I../../src

all: ebpf
clean:
	$(RM) ebpf

ebpf: ebpf.c ../../obj/einterpreter.o
	$(CC) $(CFLAGS) -o $@ $^
