"""A regex snippet with an operand its instruction can't have."""

from commands import *
from snippets6502 import register_snippet

load(0x2000, "orig/helloworld.orig", "6502")
entry(0x2000)
register_snippet(None, None, """
    asl (foo),y
""")
go()
