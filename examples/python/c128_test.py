"""A C128 program (a PRG file with a BASIC SYS line), with commodore.c128().
(Made from asm_to_create_test_binaries/c128_test.asm.)"""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6502", "f33285af69217592a591a79fb0ef275a")
commodore.c128()
go()
