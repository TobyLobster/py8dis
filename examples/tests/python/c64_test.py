"""A C64 program (a PRG file with a BASIC program that SYSes to the machine
code), disassembled with commodore.c64(), which names and comments the
Kernal calls (and knows what CHROUT leaves unchanged), the hardware, the OS
workspace, the IRQ handler and the BASIC program. (Made from
asm/c64_test.asm.)"""

from commands import *
import commodore

load_prg("orig/c64_test.orig", "6510", "657fc0b303538731752e3d327d294bca")
commodore.c64()
config.set_label_references(True)
go()
