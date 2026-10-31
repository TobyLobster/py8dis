"""Redundant Z80 instructions (see
asm_to_create_test_binaries/redundant_z80.asm): an instruction whose results
are all changed again before anything uses them is commented '; Redundant
instruction?'."""

from commands import *

load(0x8000, "orig/redundant_z80.orig", "z80", "7d4deef6a9de9900ee99880d2bac5a9a")
entry(0x8000, "start")

go()
