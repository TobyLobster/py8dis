"""Loops that search a table for a byte, loops that compare two tables (with
one index register or two), and loops that clear memory with the 65C02's
STZ, commented by the built in snippets (see
py8dis/snippets6502.py and asm_to_create_test_binaries/search_loops.asm for
what each loop does)."""

from commands import *

load(0x2000, "orig/search_loops.orig", "65c02", "f6481e2ab349962766a348972f83d4bc")
entry(0x2000, "start")

label(0x211f, "key_table")
label(0x212f, "table2")
label(0x2135, "table6")
label(0x213d, "table7")
label(0x2200, "string3")
label(0x2300, "buffer4")
label(0x2328, "text5")
label(0x2428, "table8")
label(0x2438, "table9")

go()
