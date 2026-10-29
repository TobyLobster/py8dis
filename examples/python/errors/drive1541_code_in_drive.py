"""commodore.drive1541_code() in the 1541's own disassembly (drive1541()),
where all the code is the drive's."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_test.orig", "6502")
commodore.drive1541()
commodore.drive1541_code(0x0600, 0x0500, 0x10)
go()
