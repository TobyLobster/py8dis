"""A command for an address where nothing is loaded."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
comment(0x3000, "Nothing is loaded here")
go()
