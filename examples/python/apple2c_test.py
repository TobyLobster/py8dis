"""A 65C02 program (made from asm_to_create_test_binaries/apple2c_test.asm)
with apple.apple2(model="iic"): the IIc's own switches replace those of the
IIe's it lacks or differs in. Its mouse and vertical blank interrupt
switches (MOUXINT, VBLINT, ENVBL, MOUDSBL...), IOUDIS (written as IOUDISOFF
and IOUDSBL, read as RDIOUDIS), double hi-res, the 40/80-column switch and
the serial ports are named and commented, with 'Wait for the vertical blank
interrupt' for a loop on VBLINT; the slots' ROM switch it lacks isn't
named; the 65C02's STZ counts as a write (e.g. 'stz SET80VID'), and the
alternate character set has MouseText. apple2e_enhanced_test is the same
program as the enhanced IIe."""

from commands import *
import apple

load(0x0803, "orig/apple2c_test.orig", "65C02", "6ae2b9c7361cdc22cce1f2c9555cffa3")
apple.apple2(model="iic")
entry(0x0803, "start")
go()
