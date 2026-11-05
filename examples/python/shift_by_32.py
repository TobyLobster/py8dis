"""A shift by 32 or more in an expression, which py8dis doesn't work out:
xa and sjasmplus take the count modulo 32 (so '$0e >> 32' is $0e), where
the other assemblers give 0. Here it's an expression for xa that's right
for xa, which py8dis used to stop with an error, having worked it out as 0.
(The program is the hello world test's, copied by
asm_to_create_test_binaries/go.)"""

from commands import *

load(0x2000, "orig/shift_by_32.orig", "6502", "ba85fca1feae301af81806d3102b0851")
entry(0x2000)

# 'cpx #$0e', the length of the message
expr(0x200a, make_op2(make_hex(0x0e), ">>", 32))

go()
