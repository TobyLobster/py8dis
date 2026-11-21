"""What subroutines leave behind (see
asm/subroutine_summaries.asm), with the CPU state
shown after each instruction: what a subroutine doesn't change, and what's
known at all its returns, are known after a call to it, and noted before it
('On Exit') where the code after a call relies on them; a tail call leaves
what the subroutine it jumps to leaves; nothing is known after a call to a
subroutine that throws its return address away; registers and flags saved
on the stack and got back are as they were after the call, unless the
subroutine changes what it saved."""

from commands import *

load(0x2000, "orig/subroutine_summaries.orig", "6502", "d0dafbb90aca7a04585b4afdf64a4421")
entry(0x2000, "start")

config.set_show_cpu_state(True)

config.set_label_references(True)
go()
