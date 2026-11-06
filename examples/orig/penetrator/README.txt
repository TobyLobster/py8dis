penetrator.orig (in examples/orig) is Penetrator, Stefan Wessels's Apple II
remake of the ZX Spectrum game (2019), used as a test of apple.apple2() and
load_apple_file() (see python/penetrator.py). It's public domain, under the
Unlicense (LICENSE, in this folder).

It was built, unchanged, from its source in

    https://github.com/StewBC/penetrator

at commit dd6760bce30ccb1c8111250a7328d7df09a06a5c (2023-11-06), with cc65
2.19 (https://github.com/cc65/cc65), as its Makefile does:

    make TARGETS=apple2 ASFLAGS='--asm-define PADDL0=49252 --asm-define PTRIG=49264'

(cc65 2.19's apple2.inc doesn't define PADDL0 and PTRIG, which later
versions define as $C064 and $C070.) The result, penetrator.apple2, is an
AppleSingle file: a BIN file (type $06) whose aux type, its load address, is
$4000. The game's loader, built from src/apple2.loader, reads it into
memory and jumps to $6000.

md5sum:
    2d44386752659f1c243c331cae0ac984  penetrator.orig
