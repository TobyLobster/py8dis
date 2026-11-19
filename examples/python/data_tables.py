"""Tables of data that py8dis finds itself (see
asm_to_create_test_binaries/data_tables.asm): tables of bytes and words that
the code reads with an index whose possible values are known, each with a
comment saying how big it is and how it's used (marked as bytes, unless
it's text, so no string is found in or across it); two tables that overlap;
and tables of pointers that the code copies into zero page and uses, each
entry written as the label it points to. A table the control file marks
itself is left alone, as is one whose index isn't known."""

from commands import *

load(0x2000, "orig/data_tables.orig", "6502", "16b26267635e49aa7b239f3576afe123")
entry(0x2000, "start")

# The eighth table, marked here (so py8dis leaves it alone)
label(0x20ce, "table8")
byte(0x20ce, 4)

go()
