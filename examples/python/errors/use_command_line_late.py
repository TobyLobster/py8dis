"""use_command_line(False) after the command line has been read (by the first command)."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
use_command_line(False)
go()
