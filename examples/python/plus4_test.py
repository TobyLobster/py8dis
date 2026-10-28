"""A Plus/4 program (a PRG file with a BASIC SYS line), with commodore.plus4().
(Made from asm_to_create_test_binaries/plus4_test.asm.)"""

from commands import *
import commodore

load_prg("orig/plus4_test.orig", "6502", "212114c931d195facc29ebb2c7a39123")
commodore.plus4()
go()
