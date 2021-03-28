Experiment 1
============

Generate bpf programs from C functions. Some attention should be paid to
context: how would the program know what it's dealing with, what it can
call and so on.

Status
------
Seemingly in order. Much is left to understand.

Setup
-----
Write a trivial C filter program. Compile it using llvm. Look at the resulting bpf code.

Results
-------
The operations succeed.

Bibliography
------------
- https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/
