"""load() with a negative offset."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502", offset=-1)
go()
