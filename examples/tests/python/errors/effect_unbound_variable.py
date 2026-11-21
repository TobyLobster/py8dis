"""An effect pattern with a variable whose addresses aren't given."""

from commands import *
import snippets6502

load(0x2000, "orig/effect_patterns.orig", "6502")
snippets6502.register_snippet(None, None, """
    [vec] = lo
    [vec+1] = hi
""")
go()
