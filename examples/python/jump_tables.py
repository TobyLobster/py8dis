"""Jump tables that py8dis finds itself (see
asm_to_create_test_binaries/jump_tables.asm): the RTS trick, a JMP through
an address stored in zero page, a JSR whose operand is stored, and an index
with a lower bound, each with the index's possible values known from the
code before it. A table whose index isn't known isn't found (for the two
here, a word table and one with low and high bytes, py8dis prints notes of
the control file lines that would mark them: see the warning test
jump_table_suggestions, which turns the notes on), and one the control file marks itself is left
alone."""

from commands import *

load(0x2000, "orig/jump_tables.orig", "6502", "f234b0f8c18f1173424a476b0cd51718")
entry(0x2000, "start")
entry(0x20c9, "no_guard_split")

config.set_jump_table_suggestions(False)

# The sixth table, marked here as rts_code_ptr()s (so py8dis doesn't mark it
# again)
label(0x209b, "table6")
rts_code_ptr(0x209b)
rts_code_ptr(0x209d)

go()
