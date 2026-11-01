"""An 8080 program that copies a routine to &8000 and calls it there (see
asm_to_create_test_binaries/move_8080.asm), with move() for the routine and
include_binary_file() for the table at the end. With z88dk-z80asm these are
PHASE/DEPHASE and BINARY. (A regression test: they mustn't be written as
comments, which would assemble the routine at the wrong address, and leave
the table out.)"""

from commands import *

load(0x100, "orig/move_8080.orig", "8080", "dd14b3a0ceeea226dcf0dc2aeb9ff433")
# The 12 byte routine at &0114 runs at &8000
move(0x8000, 0x114, 12)
entry(0x100, "start")
# The bytes from &0120 to the end are the same as this file (which 'go' makes
# from the end of the program), so they're written as an include of it
include_binary_file(0x120, "orig/move_8080_table.bin")
go()
