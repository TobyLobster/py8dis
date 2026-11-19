"""Jump tables that py8dis finds but can't mark, since what the index can
be isn't known (see asm_to_create_test_binaries/jump_tables.asm, tables 5
and 7): it prints a note for each, of how many entries the table seems to
have and the control file lines that would mark them. (The same control
file as jump_tables.)"""

from commands import *

load(0x2000, "orig/jump_tables.orig", "6502", "f234b0f8c18f1173424a476b0cd51718")
entry(0x2000, "start")
entry(0x20c9, "no_guard_split")

label(0x209b, "table6")
rts_code_ptr(0x209b)
rts_code_ptr(0x209d)

go()
