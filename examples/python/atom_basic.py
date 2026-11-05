"""An Acorn Atom BASIC program in an ATM file (see
asm_to_create_test_binaries/atom_basic.asm), loaded with load_atm() and
marked with acorn.atom_basic_program(): each line is labelled and listed in
a comment (e.g. '; 20 P."HELLO, WORLD"'), and the machine code that line
300's LINK calls is traced and named 'link_entry'."""

from commands import *
import acorn

load_atm("orig/atom_basic.orig", "6502", "0ab0662f8b7228d619d71397a679aaff")
acorn.atom()
end = acorn.atom_basic_program()
assert end == 0x2943
# (There's no program at the machine code, so nothing is classified there)
assert acorn.atom_basic_program(0x2950) is None
go()
