"""Comments on where known registers are used (see
asm_to_create_test_binaries/register_use_comments.asm): a register set well
before it's used as an index ('Offset Y=$11') or stored ('A=0' in a loop),
memory set loops with one register as both the index and the count (counting
up to a limit, down past zero, down to zero, and through a pointer), and an
immediate operand that code changes, which isn't taken to be known."""

from commands import *

load(0x2000, "orig/register_use_comments.orig", "6502", "ca0fb446b4321d7aaaa5078aac82bf30")
entry(0x2000, "start")
label(0x2059, "table1")
label(0x2069, "table2")
label(0x2071, "table3")

go()
