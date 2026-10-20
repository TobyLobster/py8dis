# Cycle counts for branches near page boundaries, including in move()d code.
# See asm_to_create_test_binaries/cycles.asm.

from commands import *
import config

config.set_show_cycles(True)

load(0x20f0, "orig/cycles.orig", "6502", "8c4d607fc38d8c834b8d930a02a1e0a0")
move(0x30fe, 0x2105, 5)
entry(0x20f0, "start")
go()
