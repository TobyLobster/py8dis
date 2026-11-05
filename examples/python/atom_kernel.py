"""The Acorn Atom's kernel ROM (#F000-#FFFF: its OS, and the BASIC
statements and COS commands it adds), as a test on a real program, with
acorn.atom() and acorn.atom_kernel_rom(), which traces its code from the
6502's vectors, its default vectors, its command tables, its tables of plot
routines and of OSWRCH's and OSRDCH's handlers, and the routines BASIC
calls, and classifies and names its tables. The strings it prints after a
call to #F7D1 are found by acorn.atom()'s hook, and its writes to the 8255
are commented."""

from commands import *
import acorn

load(0xf000, "orig/atom_kernel.orig", "6502", "875e5e4bedde281bad88d8995fc58a20")
acorn.atom()
acorn.atom_kernel_rom()
go()
