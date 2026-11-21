"""apple.apple2() with a style of names it doesn't know."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "6502")
apple.apple2(names="commodore")
go()
