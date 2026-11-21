"""expr() with a dictionary that has no entry for the value found."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
expr(0x200a, {13: "carriage_return"})
entry(0x2000)
go()
