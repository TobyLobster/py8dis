# Regression tests for the z88dk-8080 expression operators (October 2026).
# See asm_to_create_test_binaries/regression_tests_8080.asm.
#
# make_op1('NOT', ...) used to produce '!x', which is logical NOT in
# z88dk-z80asm, and all the binary operators (AND, OR, ...) were rejected.

from commands import *

load(0x1000, "orig/regression_tests_8080.orig", "8080", "169ba41a435c2a733dc1a121f1916e96")
entry(0x1000)

constant(0x7f, "low_seven_bits")
constant(0xf0, "x_val")
constant(0x3c, "y_val")

expr(0x1001, make_and(make_op1('NOT', 'low_seven_bits'), make_hex(0xff)))  # $80
expr(0x1003, make_and('x_val', 'y_val'))                                    # $30
expr(0x1005, make_or('x_val', 'y_val'))                                     # $fc
expr(0x1007, make_eor('x_val', 'y_val'))                                    # $cc
expr(0x1009, make_divide('x_val', 16))                                      # $0f
expr(0x100b, make_modulo('x_val', 7))                                       # $02

# z88dk-z80asm has no '<' and '>' operators, and warns about an operand that
# is in brackets
constant(0x1234, "addr_val")
expr(0x100d, make_lo('addr_val'))                                           # $34
expr(0x100f, make_hi('addr_val'))                                           # $12
expr(0x1011, make_lo(make_add('addr_val', 1)))                              # $35
expr(0x1013, "(addr_val + 1)")                                              # $1235

go()
