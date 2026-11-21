"""load() with an offset at or past the end of the file."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502", offset=28)
go()
