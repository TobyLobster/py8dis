"""What subroutines that py8dis can't follow leave behind, as their
subroutine() declares it (see asm/declared_exits.asm):
on_exit descriptions of '(preserved)' (for a register or flag), or '(clear)'
or '(set)' (for a flag), are what's known after a call, and what's known
about zero page is kept after it, but for the addresses its
zero_page_written gives. acorn.bbc() declares them for OSWRCH (A, X and Y
preserved, D clear) and OSRDCH (X and Y), and that they write only &90 to
&FF, so a loop that prints with OSWRCH keeps its counter, and its message is
sized as a table; the control file declares them for a routine outside the
binary, and for one in it that jumps through a vector. (With the CPU state
shown after each instruction.)"""

from commands import *
import acorn

load(0x2000, "orig/declared_exits.orig", "6502", "30ddd9e1b89f862c94baef56921c4bb2")
acorn.bbc()
entry(0x2000, "start")

config.set_show_cpu_state(True)

subroutine(0x3000, "external_routine", on_exit={'x': "(preserved)", 'c': "(clear)"}, is_entry_point=False, zero_page_written=[0x81])
subroutine(0x2059, "vectored", "Jump through the vector at &0230", on_exit={'y': "(preserved)"})

config.set_label_references(True)
go()
