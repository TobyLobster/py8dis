"""An address past the top of memory."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x10001, "past_the_top")
go()
