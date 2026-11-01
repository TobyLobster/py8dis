"""commodore.c64_configuration() for a machine that isn't the C64."""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6510")
commodore.c128()
commodore.c64_configuration(0x1c10, 0x1c20, 0x35)
go()
