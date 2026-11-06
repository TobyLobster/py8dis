"""apple.slot_rom() for a slot whose ROM isn't loaded (this one is at $C700,
for slot 7)."""

from commands import *
import apple

load(0xc700, "orig/apple2_io_rpi.orig", "6502")
apple.apple2()
apple.slot_rom(6)
go()
