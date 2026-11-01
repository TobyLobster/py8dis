"""Things that used to stop py8dis with an error of its own (a Python
exception) rather than disassembling: see
asm_to_create_test_binaries/crash_fixes.asm. Each part of this control file
checks one."""

from commands import *
from align import Align

load(0x2000, "orig/crash_fixes.orig", "6502", "55b13234f38877a09090a76ce8b1e141")

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

go()
