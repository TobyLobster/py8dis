"""Every undocumented 6502 opcode, with load(..., "6510"): each is traced as
what it does, and written with its mnemonic for acme (where acme uses that
opcode), and as data bytes otherwise. Cycles and the CPU state are shown.
(Made from asm_to_create_test_binaries/undocumented_6502.asm.)"""

from commands import *

config.set_show_cycles(True)
config.set_show_cpu_state(True)

load(0x2000, "orig/undocumented_6502.orig", "6510", "7e9ced71b52b8909e29edf25e5427ca0")
entry(0x2000, "start")
go()
