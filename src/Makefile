.PHONY: all clean

CFLAGS:=-Wall -O1 -g3

all: einterpreter

einterpreter: einterpreter.c
	$(CC) $(CFLAGS) -DTEST -o $@ $<
