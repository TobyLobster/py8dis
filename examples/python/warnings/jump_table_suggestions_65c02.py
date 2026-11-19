"""A 65C02 'jmp (table,x)' whose index isn't known (see
asm_to_create_test_binaries/jump_tables_65c02.asm): py8dis can't mark the
table, so it prints a note of how many entries it seems to have and the
control file lines that would mark them. (The same control file as
jump_tables_65c02, with the notes on.)"""

from commands import *

load(0x2000, "orig/jump_tables_65c02.orig", "65c02", "0bc0426fb444995b6a943c732435eb4d")
entry(0x2000, "start")
entry(0x201d, "unguarded")

go()
