"""Two banks of Z80 code that both run at $8000, loaded separately from the
main program that calls them (see asm_to_create_test_binaries/banks_z80.asm),
as banks_test.py is for the 6502: a move() for each bank, gaps between the
parts that are loaded (which z88dk-z80asm's output pads with DEFS, since it
doesn't allow a second ORG), and calls from the main program to $8000, which
py8dis can't tell the bank of."""

from commands import *

# The main program, and each bank, loaded where they are in the file (at
# $1000, $2000 and $3000), with gaps between them
load(0x1000, "orig/banks_z80.orig", "z80", "fa7e6d5d59918ec5f050a47cb4420f43", length=0x11)
load(0x2000, "orig/banks_z80.orig", "z80", offset=0x1000, length=0x16)
load(0x3000, "orig/banks_z80.orig", "z80", offset=0x2000)

# Both banks run at $8000
bank_a = move(0x8000, 0x2000, 0x16)
bank_b = move(0x8000, 0x3000, 0x15)

entry(0x1000, "main")
with bank_a:
    entry(0x8000, "bank_a")
with bank_b:
    entry(0x8000, "bank_b")

# The second call is to bank B's entry point (bank_select is 1)
expr(0x100e, "bank_b")

go()
