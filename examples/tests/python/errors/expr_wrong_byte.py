"""expr() whose value py8dis can work out, and which is wrong: the byte at &200a (cpx #&0e) is 14, not 15."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
constant(13, "length")
expr(0x200a, make_add("length", 2))
entry(0x2000)
go()
