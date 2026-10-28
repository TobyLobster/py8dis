"""A C128 program (a PRG file with a BASIC SYS line), with commodore.c128().
(Made from asm_to_create_test_binaries/c128_test.asm.)"""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6502", "c8e16e878f5125aa538550eece285be3")
commodore.c128()
go()
