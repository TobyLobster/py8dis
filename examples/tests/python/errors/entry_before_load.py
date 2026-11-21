"""entry() before load(), which chooses the CPU that entry points are given
to."""

from commands import *

entry(0x2000)
load(0x2000, "orig/helloworld.orig", "6502")
go()
