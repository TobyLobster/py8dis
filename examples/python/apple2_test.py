"""An Apple II+ program (made from asm_to_create_test_binaries/apple2_test.asm)
with apple.apple2(): the Monitor's routines are named, and their calls
commented (e.g. "Print 'H'", 'Print 5 spaces', 'Send output to slot 1
(PR#1)', WAIT's delay); runs of characters printed with COUT are commented
('Print "HI"'), and so is a DOS command printed after a Ctrl-D; the loop
that prints a message is recognised; the zero page, the soft switches and
the vectors are named; and the handlers that the reset vector, the output
hook (CSW) and the IRQ vector are set to are traced and named; and what's
done with the soft switches and the language card is commented, and the
Disk II's switches, indexed by the slot, named. The IIe's AUXMOVE, status
switch and write-only switches aren't named, since this is a II+."""

from commands import *
import apple

load(0x0803, "orig/apple2_test.orig", "6502", "9b67f7c1ea43e09878f82ace39566579")
apple.apple2()
entry(0x0803, "start")
go()
