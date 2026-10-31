"""Redundant instructions (see asm_to_create_test_binaries/redundant_test.asm):
an instruction whose results are all changed again before anything uses them
is commented '; Redundant instruction?', unless it reads I/O (named with
io_range()), or code jumps into it (the BIT trick)."""

from commands import *

load(0x2000, "orig/redundant_test.orig", "6502", "9fb15206314374383ba045695900318d")
io_range(0xfe00, 0xff00)
entry(0x2000, "start")
label(0x2003, "middle")

go()
