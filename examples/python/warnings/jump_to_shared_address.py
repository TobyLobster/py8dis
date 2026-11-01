"""A call to an address that two moves put code at (two banks that both run
at $8000), from code that isn't in either, so py8dis can't tell which bank
it reaches: it warns, and doesn't trace it (see banks_test.py)."""

from commands import *

load(0x1000, "orig/banks_test.orig", "6502", length=0x10)
load(0x2000, "orig/banks_test.orig", "6502", offset=0x1000, length=0x1a)
load(0x3000, "orig/banks_test.orig", "6502", offset=0x2000)
move(0x8000, 0x2000, 0x1a)
move(0x8000, 0x3000, 0x19)
entry(0x1000)
go()
