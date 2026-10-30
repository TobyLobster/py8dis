"""The Z80's undocumented opcodes (see
asm_to_create_test_binaries/undocumented_z80.asm). They're traced as what
they do. Those z88dk-z80asm accepts (e.g. 'ld ixh,a', 'sll b', 'rlc
(ix+2),b', 'in f,(c)') are written as instructions; the others (duplicates
such as ED 4C, another NEG; ED opcodes that do nothing; and a DD or FD
prefix before an instruction that doesn't use HL, which does nothing) are
written as data bytes, with the instruction in a comment."""

from commands import *

load(0x8000, "orig/undocumented_z80.orig", "z80", "a51c64340458f3bea1a45f72a78d8aac")
entry(0x8000, "start")

label(0x807a, "finish")
label(0x807c, "word")
word(0x807c)

config.set_show_cycles(True)

go()
