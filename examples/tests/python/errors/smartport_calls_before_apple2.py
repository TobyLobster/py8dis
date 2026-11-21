"""apple.smartport_calls() before apple.apple2()."""

from commands import *
import apple

load(0x0803, "orig/smartport_test.orig", "6502")
apple.smartport_calls(0x085b)
go()
