"""commodore.kernal_rom() for the 1541, which has no Kernal (its DOS ROM is
traced with dos_rom())."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_test.orig", "6502")
commodore.drive1541()
commodore.kernal_rom()
go()
