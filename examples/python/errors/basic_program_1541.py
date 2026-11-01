"""commodore.basic_program() with no address after drive1541(): the 1541 has
no BASIC, so there's nowhere for its program to be by default."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_test.orig", "6502")
commodore.drive1541()
commodore.basic_program()
go()
