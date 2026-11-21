"""apple.apple2() after another machine's set-up (acorn.atom())."""

from commands import *
import acorn
import apple

load(0x0803, "orig/apple2_test.orig", "6502")
acorn.atom()
apple.apple2()
go()
