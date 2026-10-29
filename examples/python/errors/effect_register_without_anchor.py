"""An effect pattern with a register line but no anchor (an instruction to
test the register just before)."""

from commands import *
import snippets6502

load(0x2000, "orig/effect_patterns.orig", "6502")
snippets6502.register_snippet(None, None, """
    [$70] = n
    x = 5
""")
go()
