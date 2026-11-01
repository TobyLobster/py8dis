"""A C64 program with code for the 1541 disk drive in it (made from
asm_to_create_test_binaries/drive_code_names.asm), disassembled with
commodore.c64() and commodore.drive1541_code(). The C64 code and the drive
code both use $0300, the C64 code first: the C64 code must get the C64's
name for it (its IERROR vector) and the drive code the 1541's (its buffer
0). The drive code used to get the C64's name, since the C64's name was
chosen first."""

from commands import *
import commodore

load_prg("orig/drive_code_names.orig", "6502", "195791e1b8956cd255abb6124c5a8c70")
commodore.c64()
commodore.drive1541_code(0x0500, 0x0813, 7)
go()
