"""acorn.atom() after acorn.bbc(), which has already chosen the machine."""

from commands import *
import acorn

load(0x2900, "orig/atom_test.orig", "6502")
acorn.bbc()
acorn.atom()
go()
