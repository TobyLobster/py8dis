"""An effect pattern with two instruction lines (it can have only one
anchor)."""

from commands import *
import snippets6502

load(0x2000, "orig/effect_patterns.orig", "6502")
snippets6502.register_snippet(None, None, """
    [$70] = n
    ldx #5
    jsr $2073
""")
go()
