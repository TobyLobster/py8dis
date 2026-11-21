"""load() of a file that doesn't exist."""

from commands import *

load(0x2000, "orig/no_such_file.orig", "6502")
go()
