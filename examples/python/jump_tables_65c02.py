"""The 65C02's 'jmp (table,x)' (see
asm_to_create_test_binaries/jump_tables_65c02.asm): X is 0, 2, 4 or 6, so
py8dis finds the table of four words and traces the code they point to.
The second table's index isn't known, so it isn't marked (py8dis prints a
note of the control file lines that would mark it: see the warning test
jump_table_suggestions_65c02, which turns the notes on)."""

from commands import *

load(0x2000, "orig/jump_tables_65c02.orig", "65c02", "0bc0426fb444995b6a943c732435eb4d")
entry(0x2000, "start")
entry(0x201d, "unguarded")

config.set_jump_table_suggestions(False)

config.set_label_references(True)
go()
