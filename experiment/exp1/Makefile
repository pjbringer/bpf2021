.PHONY: all clean view view2
all: exp1.o
clean:
	$(RM) exp1.o

exp1.o: exp1.c
	clang -c -target bpf -O -o $@ $^

view: exp1.o
	readelf -x .text $^

view2: exp1.o
	llvm-objdump -d $^
