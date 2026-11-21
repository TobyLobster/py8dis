"""apple.apple2() for the II+ with the 65C02, which it doesn't have."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "65C02")
apple.apple2()
go()
