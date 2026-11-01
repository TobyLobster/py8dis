"""Redundant instructions (see asm_to_create_test_binaries/redundant_test.asm):
an instruction whose results are all changed again before anything uses them
is commented '; Redundant instruction?', unless it reads I/O (named with
io_range()), or code jumps into it (the BIT trick)."""

from commands import *

load(0x2000, "orig/redundant_test.orig", "6502", "9fb15206314374383ba045695900318d")
# The program reads $fe40, which is I/O: reading it can have side effects, so
# a load from it isn't redundant even if the value loaded isn't used
io_range(0xfe00, 0xff00)
entry(0x2000, "start")
# The BIT trick: the byte at $2002 is a BIT opcode that hides the 'lda #4' at
# $2003, which code later branches to; so the BIT isn't redundant
label(0x2003, "middle")

go()
