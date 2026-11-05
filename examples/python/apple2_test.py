"""An Apple II+ program (made from asm_to_create_test_binaries/apple2_test.asm)
with apple.apple2(): the Monitor's routines are named, and their calls
commented (e.g. "Print 'H'", 'Print 5 spaces', 'Send output to slot 1
(PR#1)', WAIT's delay); runs of characters printed with COUT are commented
('Print "HI"'), and so is a DOS command printed after a Ctrl-D; the loop
that prints a message is recognised; the zero page, the soft switches and
the vectors are named; and the handlers that the reset vector, the output
hook (CSW) and the IRQ vector are set to are traced and named. The IIe's
AUXMOVE and status switch aren't named, since this is a II+."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "6502", "f9ffa936d54ad7c86175faba49305b06")
apple.apple2()
entry(0x0803, "start")
go()
