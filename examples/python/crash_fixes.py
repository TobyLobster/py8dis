"""Things that used to stop py8dis with an error of its own (a Python
exception) rather than disassembling: see
asm_to_create_test_binaries/crash_fixes.asm. Each part of this control file
checks one."""

from commands import *
from align import Align

load(0x2000, "orig/crash_fixes.orig", "6502", "008d8c55c653b382fc307a307795403d")

# A split asked for inside an instruction, before it's traced: the
# instruction is written as bytes (as it is if the split is asked for after
# tracing), and tracing carries on after it
split_classification(0x2001)
entry(0x2000, "start")

# substitute_constants() for an instruction with no operand: the value
# get_value returns in A is named
substitute_constants("rts", "a", {3: "three"}, define_all_constants=False)

# A constant with 'align' but no comment
constant(5, "five", align=Align.BEFORE_LINE)

# Words with a split asked for at an odd address, inside a word: they're
# written as bytes
split_classification(0x2012)
word(0x2011, 2)

# Two banks that both run at $8000, and expr_label() at $8000 outside a
# 'with' block for either: the expression goes with the code that isn't
# moved (the 'lda $8000' in the main program), as a name would
move(0x8000, 0x2015, 4)
move(0x8000, 0x2019, 4)
label(0x7fff, "before_banks")
expr_label(0x8000, "before_banks+1")

# A table entry, a name (whose last character has bit 7 set) then an
# address high byte first, read with get_u16_be_binary() at the address
# stringhi() returns, as a control file for a table of commands does. That
# address is a runtime address, which get_u8_binary() etc. take as a binary
# address: with no move there, it's the same address.
after_name = stringhi(0x201d, include_terminator_fn=lambda c: True)
assert get_u16_be_binary(after_name) == 0x2000
assert get_u16_binary(after_name) == 0x0020
assert get_u8_binary(after_name) == 0x20
byte(after_name, 2)
expr(after_name, make_hi("start"))
expr(after_name + 1, make_lo("start"))

go()
