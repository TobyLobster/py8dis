"""load() with an offset and length that run past the end of the file."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502", offset=20, length=10)
go()
