# A move whose source ends exactly at the top of memory (&10000) used to fail.
# See asm_to_create_test_binaries/move_from_top_of_memory.asm.

from commands import *

load(0xffe0, "orig/move_from_top_of_memory.orig", "6502", "7399e91f76e85b92c3805b221e5b7f39")
move(0x0900, 0xfff0, 0x10)
entry(0x0900, "start")
go()
