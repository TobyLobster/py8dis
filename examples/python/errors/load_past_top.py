"""load() of a file that would run past the top of memory."""

from commands import *

load(0xfff0, "orig/helloworld.orig", "6502")
go()
