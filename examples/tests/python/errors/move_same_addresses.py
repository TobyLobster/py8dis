"""A move() whose source and destination are the same."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
move(0x2000, 0x2000, 0x10)
go()
