# Regression tests for bugs fixed in October 2026.
# See asm_to_create_test_binaries/regression_tests.asm for what each part tests.

from commands import *

load(0x2000, "orig/regression_tests1.orig", "6502", "ddb58b6e5436655daa93ae6f3c033220")

# An entry point added *before* a second load() must not be forgotten
entry(0x2000, "start")

load(0x2080, "orig/regression_tests2.orig", "6502", "943531ce6ffc8d0a80a6de8b06d62839")

entry(0x2080, "part2")

# on_exit has no entry for X (used after the call), and bracketed descriptions
# are private: shown in the header but not used to comment calling code.
subroutine(0x202f, "store_value", "Store a value",
    on_entry={'a': "value to store", 'y': "(ignored)"},
    on_exit={'a': "(corrupted)", 'y': "count"})

# hook=False turns off decoration of calling code
subroutine(0x2036, "quiet_routine", "Quiet routine", hook=False)

go()
