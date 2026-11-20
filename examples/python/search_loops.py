"""Loops that search a table for a byte, and loops that clear memory with
the 65C02's STZ, commented by the built in snippets (see
py8dis/snippets6502.py and asm_to_create_test_binaries/search_loops.asm for
what each loop does)."""

from commands import *

load(0x2000, "orig/search_loops.orig", "65c02", "8d4c2abe37b756795edd8f7f6cb684d5")
entry(0x2000, "start")

label(0x20a3, "key_table")
label(0x20b3, "table2")
label(0x20b9, "table6")
label(0x20c1, "table7")
label(0x2200, "string3")
label(0x2300, "buffer4")
label(0x2328, "text5")
label(0x2428, "table8")
label(0x2438, "table9")

go()
