"""A move() whose destination ends exactly at the top of memory (&10000): the
file is 32 bytes loaded at &2000, and its last 16 bytes, &2010-&201f, run at
&fff0-&ffff (see asm_to_create_test_binaries/move_to_top_of_memory.asm). A
regression test: py8dis mustn't fail on this."""

from commands import *

load(0x2000, "orig/move_to_top_of_memory.orig", "6502", "8ee64467ccf6acbdb6203cbeb93b9687")
move(0xfff0, 0x2010, 0x10)
entry(0x2000, "start")
go()
