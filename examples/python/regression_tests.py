# Regression tests for bugs fixed in October 2026.
# See asm_to_create_test_binaries/regression_tests.asm for what each part tests.

from commands import *

load(0x2000, "orig/regression_tests1.orig", "6502", "b31f72fa7656b3705825819c536046ee")

# An entry point added *before* a second load() must not be forgotten
entry(0x2000, "start")

load(0x2080, "orig/regression_tests2.orig", "6502", "e823b88a32f8d8f427743572b92694f0")

entry(0x2080, "part2")

# on_exit has no entry for X (used after the call), and bracketed descriptions
# are private: shown in the header but not used to comment calling code.
subroutine(0x202f, "store_value", "Store a value",
    on_entry={'a': "value to store", 'y': "(ignored)"},
    on_exit={'a': "(preserved)", 'y': "count"})

# no_automatic_comment() suppresses the decoration of calling code, which it
# used not to (the call at &2004 still gets the 'Store a value' comment)
no_automatic_comment(0x2080)

# hook=False turns off decoration of calling code
subroutine(0x2036, "quiet_routine", "Quiet routine", hook=False)

# make_op1() used to crash for operators the assembler translates (e.g. NOT).
# 'ldx #&80' at &2020 becomes 'ldx #NOT(low_seven_bits) AND &ff' (or equivalent).
# The address is also marked with no_automatic_comment(), which used to make
# expr() silently do nothing, and then crash.
constant(0x7f, "low_seven_bits")
no_automatic_comment(0x2021)
expr(0x2021, make_and(make_op1('NOT', 'low_seven_bits'), make_hex(0xff)))

# A zero length stringn() used to fail, and a stringhi() that reaches the end
# of the loaded data without finding a top-bit-set terminator used to crash.
stringn(0x2084)
stringhi(0x2089)

# rts_code_ptr() of &ffff means the code is at &0000. This used to fail.
rts_code_ptr(0x2085)
rts_code_ptr(0x2088, 0x2087)        # low byte at &2088, high byte at &2087

# Local labels: the same name for two different addresses used to give a
# 'Symbol already defined' error from the assembler (the second becomes
# 'temp_2', with a warning), and the same name and address in two ranges used
# to be defined twice. Also, local_label() used to crash if it was the first
# label for an address.
local_label(0x71, "temp", 0x2007, 0x2009)       # stx &71
local_label(0x72, "temp", 0x2009, 0x200b)       # sty &72
local_label(0x70, "value", 0x2016, 0x2018)      # lda &70
local_label(0x70, "value", 0x201e, 0x2020)      # lda &70

# The "Memory locations" list is grouped by memory region. A label goes in the
# smallest region containing it, so this takes precedence over the 6502's zero
# page.
memory_region(0x70, 0x73, "Workspace")

# An empty name removes the region with that range. Removing this one leaves
# &72 in Workspace, the next larger region containing it.
memory_region(0x72, 0x73, "Temporary")
memory_region(0x72, 0x73, "")

# Removing the 6502's zero page leaves l0000 in no region, so it goes under
# "Other".
memory_region(0x00, 0x100, "")

# Joining text and a label, either way round, gives text whose label is named
# when it's output. ("text" + get_label(...) used to be an error.)
comment(0x200b, "Calls " + get_label(0x2036, 0x200c, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE), inline=True)
comment(0x200b, get_label(0x2036, 0x200c, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE) + " is quiet", inline=True)

# A snippet whose pattern has '.' (any instruction) where the code has
# 'cpx #4' used not to match, since the wildcard's pattern for opcode &e0 was
# wrong. It matches, so the code at &2037 is traced and commented.
import snippets6502
snippets6502.register_comment_code_snippet("Found by a snippet with a wildcard", """
    ldy #3
    .
    sta $73
""")

# The same snippet also matches from the second byte of 'bit $03a0' at &203e.
# A match that starts in the middle of an instruction used to be traced as
# code too (so the BIT was shown with an 'overlapping: ldy #3' line). Snippets
# are now matched once the code has been traced, and a match that starts
# inside an instruction is ignored.
entry(0x203e, "mid_instruction_snippet")

go()
