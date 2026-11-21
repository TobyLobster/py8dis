"""commodore.drive1541() with a ROM that isn't the 1541's or the 1541-II's."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_test.orig", "6502")
commodore.drive1541(rom="1571")
go()
