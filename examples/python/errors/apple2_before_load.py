"""apple.apple2() before load()."""

from commands import *
import apple

apple.apple2()
load(0x0803, "orig/apple2_test.orig", "6502")
go()
