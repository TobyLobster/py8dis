"""A VIC-20 program (a PRG file with a BASIC SYS line), with commodore.vic20(),
for an unexpanded VIC-20 (loaded at &1001, with the screen at &1e00 and its
colour RAM at &9600). vic20() works out the RAM expansion from where it's
loaded. (Made from asm_to_create_test_binaries/vic20_test.asm.)"""

from commands import *
import commodore

load_prg("orig/vic20_test.orig", "6502", "c63ca3cb1bc32e94f427140de9a4f2d1")
commodore.vic20()
go()
