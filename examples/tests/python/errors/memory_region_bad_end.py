"""memory_region() whose end isn't after its start."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
memory_region(0x80, 0x70, "Workspace")
go()
