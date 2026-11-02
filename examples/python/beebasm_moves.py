"""A block of code stored at &a000 that runs at &4010, over the end of the
program at &4000 (made from asm_to_create_test_binaries/beebasm_moves.asm),
loaded as two parts with a gap between them. beebasm assembles a moved
block at its runtime address, so the output copies the 16 bytes of the
program that are in the way somewhere else first, and back afterwards.
py8dis used to copy everything from &4010 up to &a000, for which there's no
room, and stopped with an error."""

from commands import *

load(0x4000, "orig/beebasm_moves.orig", "6502", "2e3f8dac0b869224191587ecef9adc8d", length=0x20)
load(0xa000, "orig/beebasm_moves.orig", "6502", offset=0x6000)
move(0x4010, 0xa000, 0x10)
entry(0x4000, "start")
go()
