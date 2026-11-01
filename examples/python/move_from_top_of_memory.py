"""A move() whose source ends exactly at the top of memory (&10000): the file
is 32 bytes loaded at &ffe0, and its last 16 bytes, &fff0-&ffff, run at
&0900 (see asm_to_create_test_binaries/move_from_top_of_memory.asm). A
regression test: py8dis mustn't fail on this."""

from commands import *

load(0xffe0, "orig/move_from_top_of_memory.orig", "6502", "7399e91f76e85b92c3805b221e5b7f39")
move(0x0900, 0xfff0, 0x10)
# The code starts in the moved block (&0900 is a runtime address)
entry(0x0900, "start")
go()
