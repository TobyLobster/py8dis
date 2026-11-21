"""commodore.c128_bank() with a bank the Kernal doesn't have."""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6502")
commodore.c128()
commodore.c128_bank(0x1c10, 0x1c20, 16)
go()
