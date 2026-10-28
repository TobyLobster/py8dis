"""A C128 program (a PRG file with a BASIC SYS line), with commodore.c128().
(Made from asm_to_create_test_binaries/c128_test.asm.)"""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6502", "3501b69daf1bc30029932ee1a9f5fbb5")
commodore.c128()
go()
