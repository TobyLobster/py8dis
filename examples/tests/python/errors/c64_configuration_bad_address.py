"""commodore.c64_configuration() with an end address past $10000."""

from commands import *
import commodore

load_prg("orig/c64_test.orig", "6510")
commodore.c64()
commodore.c64_configuration(0x0810, 0x12345, 0x35)
go()
