"""The 65C02's 'jmp (table,x)' (see
asm_to_create_test_binaries/jump_tables_65c02.asm): X is 0, 2, 4 or 6, so
py8dis finds the table of four words and traces the code they point to."""

from commands import *

load(0x2000, "orig/jump_tables_65c02.orig", "65c02", "16bd04d1c0da1f2a842ad35d9b837f4f")
entry(0x2000, "start")

go()
