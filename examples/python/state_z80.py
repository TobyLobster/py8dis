"""What py8dis knows about the Z80's registers and flags (see
asm_to_create_test_binaries/state_z80.asm), shown after each instruction:
arithmetic and the flags, 16 bit registers, IX and IY and their halves, the
alternate registers, and what's known after a conditional jump, return or
DJNZ isn't taken (and once LDIR or OTIR has finished)."""

from commands import *

load(0x8000, "orig/state_z80.orig", "z80", "a4cee08723e85f9eacd06ff70b2606b2")
entry(0x8000, "start")

config.set_show_cpu_state(True)

go()
