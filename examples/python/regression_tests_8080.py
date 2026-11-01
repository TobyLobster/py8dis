"""Regression tests for the z88dk-z80asm expression operators, for the 8080
(see asm_to_create_test_binaries/regression_tests_8080.asm): each immediate
operand is written as an expression with the same value. make_op1('NOT',
...) must give '~x', not '!x', which is logical NOT in z88dk-z80asm, and the
binary operators (AND, OR, ...) must be accepted. The comment after each
expr() is the value."""

from commands import *

load(0x1000, "orig/regression_tests_8080.orig", "8080", "169ba41a435c2a733dc1a121f1916e96")
entry(0x1000)

# Show the cycles each instruction takes, and the registers and flags known
# after it (for the 8080 too)
config.set_show_cycles(True)
config.set_show_cpu_state(True)

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
# is in brackets (so the low and high bytes are written with '& $ff' and
# '>> 8', and an operand that starts with a bracket has a '+' before it)
constant(0x1234, "addr_val")
expr(0x100d, make_lo('addr_val'))                                           # $34
expr(0x100f, make_hi('addr_val'))                                           # $12
expr(0x1011, make_lo(make_add('addr_val', 1)))                              # $35
expr(0x1013, "(addr_val + 1)")                                              # $1235

go()
