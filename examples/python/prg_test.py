"""A Commodore PRG file, loaded with load_prg() at the address in its first
two bytes. The output starts with those two bytes, so that it assembles to
the whole PRG file. (Made from asm_to_create_test_binaries/prg_test.asm.)"""

from commands import *

# load_prg() returns the address the PRG file loads at (its first two bytes)
start = load_prg("orig/prg_test.orig", "6502", "95a4a3427707b3eeed976ac7854affcb")
assert start == 0x0801

# The BASIC program 10 SYS2061, marked by hand (commodore.c64() would do
# this itself): the link to the next line, the line number, the SYS token,
# "2061", the zero at the end of the line, and the zero link that ends the
# program
comment(0x0801, "10 SYS2061")
word(0x0801, 2)
byte(0x0805)
string(0x0806, 4)
byte(0x080a, 3)

label(0xffd2, "chrout")
entry(0x080d, "start")
go()
