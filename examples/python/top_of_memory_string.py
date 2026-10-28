"""Data at the top of memory (see asm_to_create_test_binaries/top_of_memory.asm),
not traced as code: autostring() finds the printable bytes at &fffd-&ffff, a
string that runs up to the top of memory. This used to crash py8dis."""

from commands import *

load(0xffe0, "orig/top_of_memory_string.orig", "6502", "330856f6a6272f61f8224a916847a259")
go()
