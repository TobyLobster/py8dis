bbcbasic.orig (in examples/orig) is BBC BASIC (Z80) for CP/M, by R.T. Russell
(version 3.00, 1987), used as a test of the Z80 (see python/bbcbasic.py). It's
distributed under the zlib licence (COPYING, in this folder): R.T. Russell
released the source under it in 2019, and J.B. Langston's version, used
here, modifies it to assemble with z88dk-z80asm.

It was built, unchanged, from its source in

    https://github.com/jblang/bbcbasic-z80

at commit 1bd95c940cdacb41a5ee2c6c782968df37404297 (2024-06-21), with
z88dk-z80asm (v2.4), as its Makefile does:

    z88dk-z80asm -obbcbasic.com -b -m main.asm exec.asm eval.asm fpp.asm hardware.asm cpm.asm ram.asm

which also wrote bbcbasic.map (in this folder), whose labels the control
file uses.

md5sum:
    78fde24b36c65ab407df934fd8da3004  bbcbasic.orig (bbcbasic.com)
