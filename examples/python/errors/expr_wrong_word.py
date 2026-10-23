"""expr() for a word (lda &200e,x) whose value is wrong."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x200e, "message")
expr(0x2003, make_add("message", 1))
entry(0x2000)
go()
