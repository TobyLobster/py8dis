"""Data at the top of memory (see asm_to_create_test_binaries/top_of_memory.asm),
not traced as code: autostring() finds the printable bytes at &fffd-&ffff, a
string that runs up to the top of memory. (A regression test: py8dis mustn't
crash on a string that ends at &ffff.)"""

from commands import *

# No entry point, so the whole file is data
load(0xffe0, "orig/top_of_memory_string.orig", "6502", "330856f6a6272f61f8224a916847a259")
go()
