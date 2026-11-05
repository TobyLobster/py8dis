"""apple.apple2() with a model it doesn't know (yet)."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "6502")
apple.apple2(model="iic")
go()
