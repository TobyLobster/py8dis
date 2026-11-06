"""apple.slot_rom() before apple.apple2(), which sets up the names it uses."""

from commands import *
import apple

load(0xc700, "orig/apple2_io_rpi.orig", "6502")
apple.slot_rom(7)
go()
