"""An 8080 program that copies a routine to &8000 and calls it there (see
asm_to_create_test_binaries/move_8080.asm), with move() for the routine and
include_binary_file() for the table at the end. With z88dk-z80asm these are
PHASE/DEPHASE and BINARY. (They used to be written as comments, so the
routine was assembled at the wrong address, and the table was left out.)"""

from commands import *

load(0x100, "orig/move_8080.orig", "8080", "dd14b3a0ceeea226dcf0dc2aeb9ff433")
move(0x8000, 0x114, 12)
entry(0x100, "start")
include_binary_file(0x120, "orig/move_8080_table.bin")
go()
