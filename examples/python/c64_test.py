"""A C64 program (a PRG file with a BASIC program that SYSes to the machine
code), disassembled with commodore.c64(), which names and comments the
Kernal calls, the hardware, the OS workspace, the IRQ handler and the BASIC
program. (Made from asm_to_create_test_binaries/c64_test.asm.)"""

from commands import *
import commodore

load_prg("orig/c64_test.orig", "6510", "edfe1298d5cffb5b0c85432f3b17f40f")
commodore.c64()
go()
