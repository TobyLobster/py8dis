"""An Acorn Atom ATM file (see asm_to_create_test_binaries/atm_test.asm),
loaded with load_atm(): the data is loaded at the load address in its
22-byte header, and the code at its execution address (after a message) is
traced. The output starts with the header, so it assembles to the whole
ATM file."""

from commands import *
import acorn

start = load_atm("orig/atm_test.orig", "6502", "ad3d9da00024294445d21744ee3f5e3e")
assert start == 0x2900
acorn.atom()
go()
