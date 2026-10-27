"""A VIC-20 cartridge, with commodore.is_cartridge() for its header (at
&a000), and commodore.vic20(). (Made from
asm_to_create_test_binaries/vic20_cartridge_test.asm.)"""

from commands import *
import commodore

load(0xa000, "orig/vic20_cartridge_test.orig", "6502", "9596066f8efb9ab79f7d5601664dd74d")
commodore.vic20()
commodore.is_cartridge()
go()
