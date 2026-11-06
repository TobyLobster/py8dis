"""apple.slot_rom() for a slot that isn't 1 to 7."""

from commands import *
import apple

load(0xc700, "orig/apple2_io_rpi.orig", "6502")
apple.apple2()
apple.slot_rom(8)
go()
