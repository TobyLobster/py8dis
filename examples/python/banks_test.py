"""Two banks of code that both run at $8000, loaded separately from the main
program that calls them (see asm_to_create_test_binaries/banks_test.asm): a
move() for each bank, each with its own labels, gaps between the parts that
are loaded, and a call from the main program to $8000, which py8dis can't
tell the bank of (so it gives a warning, and the banks are traced from their
own entry points)."""

from commands import *

# The main program, and each bank, loaded where they are in the file (at
# $1000, $2000 and $3000), with gaps between them
load(0x1000, "orig/banks_test.orig", "6502", "3abd8e7adc86cdd009aa12698d42e4da", length=0x10)
load(0x2000, "orig/banks_test.orig", "6502", offset=0x1000, length=0x1a)
load(0x3000, "orig/banks_test.orig", "6502", offset=0x2000)

# Both banks run at $8000
bank_a = move(0x8000, 0x2000, 0x1a)
bank_b = move(0x8000, 0x3000, 0x19)

entry(0x1000, "main")
with bank_a:
    entry(0x8000, "bank_a")
with bank_b:
    entry(0x8000, "bank_b")

# The second call is to bank B's entry point (bank_select is 1)
expr(0x100c, "bank_b")

go()
