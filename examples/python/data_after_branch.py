"""Data after a branch that's always taken (see
asm_to_create_test_binaries/data_after_branch.asm): bytes that tracing ran
into past a branch that turns out to be always taken, which the code reads as
a table, and which as code run straight into an opcode that doesn't exist,
are a table after all. Bytes that could be code (ending in RTS), or that a
branch elsewhere goes to, are left as code. Bytes there that the control file
marks as data get no '; overlapping' comments for the instructions tracing
found in them, unless one of those is a jump or call (whose target was
traced)."""

from commands import *

load(0x2000, "orig/data_after_branch.orig", "6502", "c483abe53ed3a5ee10e2dc1f34f37e58")
entry(0x2000, "start")

# Bytes after an always-taken branch that are data (as code, 'sty $86 : sty
# $e298', and 'sty $86 : jsr $3000')
label(0x2054, "table4")
byte(0x2054, 6)
label(0x205f, "table5")
byte(0x205f, 6)

go()
