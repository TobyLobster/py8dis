"""Every documented Z80 instruction (see
asm_to_create_test_binaries/test_z80.asm), assembled with z88dk-z80asm
-mz80."""

from commands import *

load(0x8000, "orig/test_z80.orig", "z80", "7bb167047d0b031b6be0f8a1b47bcc1f")
entry(0x8000, "start")

# (After 'jp (hl)', 'reti' and 'retn', which tracing doesn't go past)
entry(0x8580, "interrupt")
entry(0x8582, "nmi")
entry(0x8585, "jump_ix")
entry(0x8587, "jump_iy")

label(0x852c, "loop")
label(0x8577, "subroutine")
label(0x8584, "finish")
byte(0x8589)
label(0x8589, "value")
word(0x858a)
label(0x858a, "word")
label(0x858c, "table")
byte(0x858c, 4)

# (A test of each instruction, rather than a program, so most of its
# instructions' results aren't used)
config.set_redundant_instruction_comments(False)
config.set_show_cycles(True)

go()
