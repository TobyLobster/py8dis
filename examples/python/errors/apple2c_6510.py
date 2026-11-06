"""apple.apple2() for the IIc with the 6510, whose undocumented opcodes its
65C02 doesn't run."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "6510")
apple.apple2(model="iic")
go()
