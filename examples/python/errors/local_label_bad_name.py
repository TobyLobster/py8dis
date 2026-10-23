"""A local label name that isn't valid."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
local_label(0x200e, "1message", 0x2000, 0x2010)
go()
