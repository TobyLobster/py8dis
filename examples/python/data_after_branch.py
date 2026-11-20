"""Data after a branch that's always taken (see
asm_to_create_test_binaries/data_after_branch.asm): bytes that tracing ran
into past a branch that turns out to be always taken, which the code reads as
a table, and which as code run straight into an opcode that doesn't exist,
are a table after all. Bytes that could be code (ending in RTS), or that a
branch elsewhere goes to, are left as code."""

from commands import *

load(0x2000, "orig/data_after_branch.orig", "6502", "a28293bf85052789b3d3167f5d66e705")
entry(0x2000, "start")

go()
