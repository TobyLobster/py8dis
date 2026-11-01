"""Z80 code that used to stop py8dis with an error of its own (a Python
exception) rather than disassembling: see
asm_to_create_test_binaries/crash_fixes_z80.asm. Each part of this control
file checks one."""

from commands import *

load(0x8000, "orig/crash_fixes_z80.orig", "z80", "61fd6a8a0f7d2121c154e1a2a74f61f6")

entry(0x8000, "start")
label(0x8010, "table")

# expr() on the address in instructions with a prefix (four bytes long), as
# well as in one without
expr(0x8001, "table")
expr(0x8005, "table+2")
expr(0x8009, "table+2")
expr(0x800d, "table")

# An instruction cut off by the end of the loaded data: it's written as data
entry(0x8014, "cut_off")

go()
