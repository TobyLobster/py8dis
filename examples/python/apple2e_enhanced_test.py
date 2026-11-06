"""The program of apple2c_test (copied by the go script), with
apple.apple2(model="iie-enhanced"): the enhanced IIe has the IIe's switches
(RDCXROM, RDVBLBAR, the annunciators, PADDL2 etc.) on a 65C02, whose STZ
counts as a write (e.g. 'stz SET80VID'), and MouseText in its alternate
character set."""

from commands import *
import apple

load(0x0803, "orig/apple2e_enhanced_test.orig", "65C02", "6ae2b9c7361cdc22cce1f2c9555cffa3")
apple.apple2(model="iie-enhanced")
entry(0x0803, "start")
go()
