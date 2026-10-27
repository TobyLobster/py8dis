"""A C64 cartridge, with commodore.is_cartridge() for its header, and
commodore.c64() for the code that sets the NMI and IRQ vectors. (Made from
asm_to_create_test_binaries/cartridge_test.asm.)"""

from commands import *
import commodore

load(0x8000, "orig/cartridge_test.orig", "6502", "52bc650e68df34dbae6b49e418f8324c")
commodore.c64()
commodore.is_cartridge()
go()
