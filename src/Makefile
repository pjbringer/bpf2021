.PHONY: all clean

CFLAGS:=-Wall -O1 -g3

all: einterpreter

einterpreter: einterpreter.c interpreter.h
	$(CC) $(CFLAGS) -DTEST -o $@ $<
