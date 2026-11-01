"""A move() to below the start of the file: the 256 bytes loaded at $3001 run
at $2f01-$3000, which overlaps the file's first byte, at $3000, which isn't
moved. The file is the same as moving1.py's (the bytes 0 to 255 then a 0,
all data). For beebasm, for example, the output copies the byte at $3000
out of the way while it assembles the block at its runtime address, then
puts both back."""

from commands import *

# Load the program to be disassembled into py8dis's memory.
load(0x3000, "orig/moving3.orig", "6502")

# move(dest, source, len)
move(0x2f01, 0x3001, 256)

# Note: beebasm's COPYBLOCK, which the output uses to put the block in
# place, takes its arguments in a different order: <start>,<end>,<dest>

go()
