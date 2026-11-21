"""Loading with a different CPU from the first load()."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
load(0x3000, "orig/helloworld.orig", "65c02")
go()
