# Regression tests for bugs fixed in October 2026.
# See asm_to_create_test_binaries/regression_tests.asm for what each part tests.

from commands import *

load(0x2000, "orig/regression_tests1.orig", "6502", "ddb58b6e5436655daa93ae6f3c033220")

# An entry point added *before* a second load() must not be forgotten
entry(0x2000, "start")

load(0x2080, "orig/regression_tests2.orig", "6502", "e823b88a32f8d8f427743572b92694f0")

entry(0x2080, "part2")

# on_exit has no entry for X (used after the call), and bracketed descriptions
# are private: shown in the header but not used to comment calling code.
subroutine(0x202f, "store_value", "Store a value",
    on_entry={'a': "value to store", 'y': "(ignored)"},
    on_exit={'a': "(corrupted)", 'y': "count"})

# hook=False turns off decoration of calling code
subroutine(0x2036, "quiet_routine", "Quiet routine", hook=False)

# make_op1() used to crash for operators the assembler translates (e.g. NOT).
# 'ldx #&80' at &2020 becomes 'ldx #NOT(low_seven_bits) AND &ff' (or equivalent).
constant(0x7f, "low_seven_bits")
expr(0x2021, make_and(make_op1('NOT', 'low_seven_bits'), make_hex(0xff)))

# A zero length stringn() used to fail, and a stringhi() that reaches the end
# of the loaded data without finding a top-bit-set terminator used to crash.
stringn(0x2084)
stringhi(0x2089)

# rts_code_ptr() of &ffff means the code is at &0000. This used to fail.
rts_code_ptr(0x2085)
rts_code_ptr(0x2088, 0x2087)        # low byte at &2088, high byte at &2087

go()
