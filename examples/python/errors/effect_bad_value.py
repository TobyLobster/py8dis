"""An effect pattern with a value that isn't a number, a name or '?'."""

from commands import *
import snippets6502

load(0x2000, "orig/effect_patterns.orig", "6502")
snippets6502.register_snippet(None, None, """
    [$70] = 1+2
    jsr $2073
""")
go()
