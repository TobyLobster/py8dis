"""A C64 cartridge, with commodore.is_cartridge() for its header, and
commodore.c64() for the code that sets the NMI and IRQ vectors. (Made from
asm_to_create_test_binaries/cartridge_test.asm.)"""

from commands import *
import commodore

load(0x8000, "orig/cartridge_test.orig", "6502", "5e908240b929ffa6bbb18fde18d9114b")
commodore.c64()
commodore.is_cartridge()
go()
