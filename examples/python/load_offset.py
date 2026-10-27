"""Loading parts of a file with load(..., offset=..., length=...): the PRG
file of prg_test, without its two-byte header, in two parts. The output
assembles to the data without the header (orig/load_offset.orig)."""

from commands import *

# The BASIC program (12 bytes, after the 2 byte header), then the rest
load(0x0801, "orig/prg_test.orig", "6502", "95a4a3427707b3eeed976ac7854affcb", offset=2, length=12)
load(0x080d, "orig/prg_test.orig", "6502", offset=14)

label(0xffd2, "chrout")
entry(0x080d, "start")
go()
