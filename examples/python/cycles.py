"""Cycle counts, shown with config.set_show_cycles(True), for branches near
page boundaries (see asm_to_create_test_binaries/cycles.asm). A taken branch
takes an extra cycle if its target is in a different page from the
instruction after the branch (not the branch itself). This includes code
that's copied elsewhere to run, with move(), where it's the runtime
addresses that count."""

from commands import *
import config

config.set_show_cycles(True)

load(0x20f0, "orig/cycles.orig", "6502", "8c4d607fc38d8c834b8d930a02a1e0a0")
# The 5 bytes at $2105 run at $30fe, where their branch's next instruction
# and its target are both in the next page ($3100 and $3102)
move(0x30fe, 0x2105, 5)
entry(0x20f0, "start")
go()
