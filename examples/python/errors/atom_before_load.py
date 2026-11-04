"""acorn.atom() before load(), which chooses the CPU."""

from commands import *
import acorn

acorn.atom()
load(0x2900, "orig/atom_test.orig", "6502")
go()
