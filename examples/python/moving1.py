"""A move() to a runtime address just below where the block is loaded, so that
it overlaps data that isn't moved: the 255 bytes loaded at $3002 run at
$3001, one byte lower, over the byte loaded at $3001. The file is just the
bytes 0 to 255 then a 0, all data. The output still has to assemble to the
original file: for beebasm, for example, it copies the byte at $3001 out of
the way while it assembles the block at its runtime address, then puts both
back. (See moving2.py and moving3.py for the other ways round.)"""

from commands import *

# Load the program to be disassembled into py8dis's memory.
load(0x3000, "orig/moving1.orig", "6502")

# move(dest, source, len)
move(0x3001, 0x3002, 255)

# Note: beebasm's COPYBLOCK, which the output uses to put the block in
# place, takes its arguments in a different order: <start>,<end>,<dest>

go()
