"""Regression tests for fixed bugs: each part of this control file checks one
thing py8dis must get right. See asm_to_create_test_binaries/regression_tests.asm
for what each part of the program tests. The program is in two files, split
at &2080 (see asm_to_create_test_binaries/go), so that an entry point can be
given before the second load()."""

from commands import *

load(0x2000, "orig/regression_tests1.orig", "6502", "3e56e4b098abd910a888da106e89d503")

# An entry point added *before* a second load() must not be forgotten
entry(0x2000, "start")

load(0x2080, "orig/regression_tests2.orig", "6502", "e823b88a32f8d8f427743572b92694f0")

entry(0x2080, "part2")

# on_exit has no entry for X (used after the call), and bracketed descriptions
# are private: shown in the header but not used to comment calling code.
subroutine(0x202f, "store_value", "Store a value",
    on_entry={'a': "value to store", 'y': "(ignored)"},
    on_exit={'a': "(preserved)", 'y': "count"})

# no_automatic_comment() turns off the comments that store_value's
# subroutine() gives the call at &2080 (the call at &2004 still gets the
# 'Store a value' comment)
no_automatic_comment(0x2080)

# hook=False turns off decoration of calling code
subroutine(0x2036, "quiet_routine", "Quiet routine", hook=False)

# make_op1() with an operator the assembler translates (e.g. NOT) mustn't
# crash: 'ldx #&80' at &2020 becomes 'ldx #NOT(low_seven_bits) AND &ff' (or
# equivalent). The address is also marked with no_automatic_comment(), which
# mustn't make expr() silently do nothing (or crash).
constant(0x7f, "low_seven_bits")
no_automatic_comment(0x2021)
expr(0x2021, make_and(make_op1('NOT', 'low_seven_bits'), make_hex(0xff)))

# A zero length stringn() must work, and so must a stringhi() that reaches the
# end of the loaded data without finding a top-bit-set terminator.
stringn(0x2084)
stringhi(0x2089)

# rts_code_ptr() of &ffff means the code is at &0000 (the address wraps round).
rts_code_ptr(0x2085)
rts_code_ptr(0x2088, 0x2087)        # low byte at &2088, high byte at &2087

# Local labels: the same name for two different addresses mustn't give a
# 'Symbol already defined' error from the assembler (the second becomes
# 'temp_2', with a warning), and the same name and address in two ranges must
# be defined only once. Also, local_label() must work when it gives an address
# its first label.
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

# Joining text and a label, either way round ("text" + get_label(...), or
# get_label(...) + "text"), gives text whose label is named when it's output.
# (The label is the one for &2036 as used by the call's operand, at &200c.)
comment(0x200b, "Calls " + get_label(0x2036, 0x200c, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE), inline=True)
comment(0x200b, get_label(0x2036, 0x200c, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE) + " is quiet", inline=True)

# A snippet whose pattern has '.' (any instruction) where the code has
# 'cpx #4' must match (the wildcard's pattern must include opcode &e0, CPX #).
# It matches, so the code at &2037, which nothing calls, is traced and
# commented.
import snippets6502
snippets6502.register_comment_code_snippet("Found by a snippet with a wildcard", """
    ldy #3
    .
    sta $73
""")

# The same snippet also matches from the second byte of 'bit $03a0' at &203e.
# Snippets are matched once the code has been traced, and a match that starts
# inside an instruction is ignored, so this one mustn't be traced as code too
# (which would show the BIT with an 'overlapping: ldy #3' line).
entry(0x203e, "mid_instruction_snippet")

# Code copied to zero page, at &c0, and used before it in the output by a
# zero page instruction ('lda zp_code'). Its label must be defined at the top
# of the output: defined inline, after that use, the assemblers would take it
# to be an absolute address, making the instruction a byte longer.
move(0xc0, 0x204b, 3)
entry(0x2046, "zp_code_user")

# An optional label whose name is relative to another address's ('scratch-1'
# for &73, with 'scratch' at &74), renamed by the label maker hook: 'scratch'
# mustn't be defined too, since nothing uses it.
optional_label(0x74, "scratch")
optional_label(0x73, "scratch-1", 0x74)
def label_maker_hook(lmd):
    """Rename the label for &73 (the optional label 'scratch-1') to
    'store_target'."""
    if lmd.defined_as_runtime_addr == 0x73:
        lmd.name = "store_target"
set_label_maker_hook(label_maker_hook)

go()
