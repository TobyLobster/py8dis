"""A regex snippet with an instruction at the start of a line, where a name
is expected (an instruction must be indented)."""

from commands import *
from snippets6502 import register_snippet

load(0x2000, "orig/helloworld.orig", "6502")
entry(0x2000)
register_snippet(None, None, """
rts
""")
go()
