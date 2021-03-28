.PHONY: all

all: exp2.out.c
clean:
	$(RM) exp2.out.c

exp2.out.c: exp2.bpf
	bpf_asm -c $^ > $@
