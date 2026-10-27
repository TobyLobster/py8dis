"""A VIC-20 program (a PRG file with a BASIC SYS line), with commodore.vic20(),
for a VIC-20 with 8K or more RAM (loaded at &1201, with the screen at &1000
and its colour RAM at &9400). vic20() works out the RAM expansion from where it's
loaded. (Made from asm_to_create_test_binaries/vic20_test.asm.)"""

from commands import *
import commodore

load_prg("orig/vic20_8k_test.orig", "6502", "570078f6c6797fa96ce8b8d859bca973")
commodore.vic20()
go()
