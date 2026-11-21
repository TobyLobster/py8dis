"""Tables of data that py8dis finds itself (see
asm_to_create_test_binaries/data_tables.asm): tables of bytes and words that
the code reads with an index whose possible values are known, each with a
comment saying how big it is and how it's used (marked as bytes, unless
it's text, so no string is found in or across it); two tables that overlap;
and tables of pointers that the code copies into zero page and uses, each
entry written as the label it points to. A table with text in it has
the text as a string and the rest as bytes, ending where the table ends; a
table of words inside a table of bytes stays words. A table the control
file marks itself is left alone, as is one whose index isn't known, or is
only half known (0 to 127 after BMI, when nothing was known before)."""

from commands import *

load(0x2000, "orig/data_tables.orig", "6502", "f872be76ca97f20a51eb3cddbe348b72")
entry(0x2000, "start")
entry(0x20e9, "text_with_bytes")
entry(0x20f5, "half_known")
entry(0x20fd, "words_in_bytes")

# The eighth table, marked here (so py8dis leaves it alone)
label(0x20ce, "table8")
byte(0x20ce, 4)

config.set_label_references(True)
go()
