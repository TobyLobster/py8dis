quikman2k8.orig (in examples/orig) is Quikman 2K8, a VIC-20 game by Robert
Hurst (1984, completed in 2008), used as a test of commodore.vic20() (see
python/quikman2k8.py). It's distributed under the Artistic License 2.0
(LICENSE, in this folder).

It was built, unchanged, from its source, quikman2k8.s, in

    https://github.com/theflyingape/quikman2k8

at commit 9bd2fd82d65a525c5a56546adc1e56b830df0d3c (2016-05-08), with cc65's
ca65 and ld65 (https://github.com/cc65/cc65), as its quikman2k8.bat does:

    ca65 --cpu 6502 --listing quikman2k8.lst quikman2k8.s
    ld65 -C vic20.cfg -o quikman2k8.prg quikman2k8.o

(Current versions of ld65 need vic20.cfg's "__STACKSIZE__ = $400;" written
as "__STACKSIZE__: type = weak, value = $400;".) The assembled bytes are those
of the listing in the repository, quikman2k8.lst.

md5sum:
    1f62bcfd9f8064437e63d8917eb38454  quikman2k8.orig
