"""What subroutines that py8dis can't follow leave behind, as their
subroutine() declares it (see asm_to_create_test_binaries/declared_exits.asm):
on_exit descriptions of '(preserved)' (for a register or flag), or '(clear)'
or '(set)' (for a flag), are what's known after a call. acorn.bbc() declares
them for OSWRCH (A, X and Y preserved, D clear) and OSRDCH (X and Y), so a
loop that prints with OSWRCH keeps its counter, and its message is sized as
a table; the control file declares them for a routine outside the binary,
and for one in it that jumps through a vector. (With the CPU state shown
after each instruction.)"""

from commands import *
import acorn

load(0x2000, "orig/declared_exits.orig", "6502", "6cdc1dc65eece7cba40e6f9ddb5c1fcd")
acorn.bbc()
entry(0x2000, "start")

config.set_show_cpu_state(True)

subroutine(0x3000, "external_routine", on_exit={'x': "(preserved)", 'c': "(clear)"}, is_entry_point=False)
subroutine(0x2036, "vectored", "Jump through the vector at &0230", on_exit={'y': "(preserved)"})

go()
