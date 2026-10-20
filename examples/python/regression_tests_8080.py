# Regression tests for the z88dk-8080 expression operators (October 2026).
# See asm_to_create_test_binaries/regression_tests_8080.asm.
#
# make_op1('NOT', ...) used to produce '!x', which is logical NOT in
# z88dk-z80asm, and all the binary operators (AND, OR, ...) were rejected.

from commands import *

load(0x1000, "orig/regression_tests_8080.orig", "8080", "cbaf1af1029b25900cea6a30ee4ca341")
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

go()
