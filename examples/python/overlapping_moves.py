"""Six moved blocks laid out like the game Revs's (made from
asm_to_create_test_binaries/overlapping_moves.asm, a scaled-down copy of
Revs's layout). E runs over the start of the program, where A, D and C are
stored, and F over the end of E, some of the rest of the program and its own
start. The beebasm output assembles each block at its runtime address, so for
E and F it copies the bytes in the way somewhere else first, and back
afterwards; Baron's puts each block in its own section."""

from commands import *

load(0x1000, "orig/overlapping_moves.orig", "6502", "bdfecbe4f974bd1fdfd120e76cd6c477")
move_a = move(0x1a00, 0x1000, 0x40)
move_d = move(0x0c00, 0x1040, 0x40)
move_c = move(0x1900, 0x1080, 0x30)
move_b = move(0x1880, 0x1300, 0x40)
move_e = move(0x0fe0, 0x1400, 0x100)
move_f = move(0x14c0, 0x1540, 0xc0)

entry(0x1100, "start")
with move_a:
    entry(0x1a00, "a_entry")
with move_d:
    entry(0x0c00, "d_entry")
with move_c:
    entry(0x1900, "c_entry")
with move_b:
    label(0x1880, "b_data")
    byte(0x1880, 8)
with move_e:
    entry(0x0fe0, "e_entry")
with move_f:
    entry(0x14c0, "f_entry")
    label(0x14c1, "f_table")
    byte(0x14c1, 4)

go()
