"""A C64 program with code for the 1541 disk drive in it (see
asm_to_create_test_binaries/drive_code_fixes.asm), disassembled with
commodore.c64() and commodore.drive1541_code(). The drive code runs in the
middle of buffer 0, so $0300 isn't named 'buffer_0' (only drive code at a
buffer's first or last byte used to stop it being named), and its labels
for $0300 and $0301 are listed under '1541 drive' (they used to be under the
C64's heading, 'Vectors'); and a store of a job code to $05 isn't commented
as a job (the 1541 has no buffer 5), while one to $01 is job 1."""

from commands import *
import commodore

load_prg("orig/drive_code_fixes.orig", "6502", "7532a6bda91f8e2e804e7bb3615079fd")
commodore.c64()
commodore.drive1541_code(0x0310, 0x080e, 15)
go()
