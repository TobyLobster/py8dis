"""What's known at a label, from the ways into it (see
asm_to_create_test_binaries/joined_states.asm), shown after each
instruction: both ways in agree on a register; a guard before the label
bounds a jump table's index; a search loop's counter is bounded at the
label after the loop, so its jump table is found too. Nothing is known at
a label a JMP goes to, or at a subroutine."""

from commands import *

load(0x2000, "orig/joined_states.orig", "6502", "123b84af08f1812e8921a33e48518ec0")
entry(0x2000, "start")
string(0x2058, 4)

config.set_show_cpu_state(True)

go()
