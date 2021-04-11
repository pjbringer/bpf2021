.PHONY: all clean

CFLAGS:=-Wall -O1 -g3

all: einterpreter ../obj/einterpreter.o

einterpreter: einterpreter.c interpreter.h
	$(CC) $(CFLAGS) -DTEST -o $@ $<

../obj/einterpreter.o: einterpreter.c interpreter.h
	$(CC) $(CFLAGS) -c -o $@ $<
