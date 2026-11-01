"""A move() to a runtime address just above where the block is loaded: the 256
bytes loaded at $3001 run at $3002, one byte higher, so the block overlaps
itself and runs one byte past the end of the file. The file is the same as
moving1.py's (the bytes 0 to 255 then a 0, all data), and the output still
has to assemble to it."""

from commands import *

# Load the program to be disassembled into py8dis's memory.
load(0x3000, "orig/moving2.orig", "6502")

# move(dest, source, len)
move(0x3002, 0x3001, 256)

# Note: beebasm's COPYBLOCK, which the output uses to put the block in
# place, takes its arguments in a different order: <start>,<end>,<dest>

go()
