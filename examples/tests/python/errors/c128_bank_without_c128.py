"""commodore.c128_bank() for a machine that isn't the C128."""

from commands import *
import commodore

load_prg("orig/c64_test.orig", "6510")
commodore.c64()
commodore.c128_bank(0x0810, 0x0820, 0)
go()
