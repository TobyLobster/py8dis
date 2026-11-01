"""Regex snippets (see docs/snippets-and-hooks.md) whose operands used to be
misread or refused, matching the code in
asm_to_create_test_binaries/regex_snippets.asm. Each snippet's match is
commented, so the comment shows it matched."""

from commands import *
from snippets6502 import register_snippet

load(0x2000, "orig/regex_snippets.orig", "6502", "7fae1de06f5020e8aaf94c7bc437c09e")
entry(0x2000, "start")

# A name with an instruction after it on the same line; a negative
# immediate value (the byte $ff); a one character operand (zero page 7);
# 'A' for the accumulator; a binary value written with '.' and '#'; and a
# branch's offset in hex
register_snippet(None, "Snippet 1 matched", """
found lda #-1
    sta 7
    asl A
    ldx #%.....#.#
    bne $01
""")

# A one character name (any address), and spaces in an operand
register_snippet(None, "Snippet 2 matched", """
    lda n
    sta $70, x
    rts
""")

go()
