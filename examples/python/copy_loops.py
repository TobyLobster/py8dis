"""Loops that copy memory, or set it, commented by the built in snippets (see
py8dis/snippets6502.py): one of each kind whose comment used to give the
wrong first byte or number of bytes (see
asm_to_create_test_binaries/copy_loops.asm for what each loop does)."""

from commands import *

load(0x2000, "orig/copy_loops.orig", "6502", "25f68cc4698f890b24d955d2a7999596")
entry(0x2000, "start")

# Expressions for two of the loops' operands, so that the comments name the
# bytes copied from them: loop 3's load (from 'table3+3', i.e. $3400, the
# source is table3+3+2) and loop 7's store (to 'table7+16', i.e. $3d00, the
# destination is table7+16+2)
label(0x33fd, "table3")
expr(0x2019, "table3+3")
label(0x3cf0, "table7")
expr(0x2050, "table7+16")

go()
