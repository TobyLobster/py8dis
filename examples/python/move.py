"""A program that copies a routine to &0900 and calls it there: the 15 bytes
at &201e are a routine that runs at &0900, so they're given with move().
The disassembly shows the routine at its runtime address, with its labels
there, and still assembles to the original file. py8dis recognises the loop
that copies the routine, and comments it. (split.py is the same program as
two files, with the routine already at &0900.)"""

from commands import *

# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are multiple versions
# of the same program.
load(0x2000, "orig/move.orig", "6502", "68a54150e8617ae1193e5a3e882998fc")

# Start tracing instructions at 0x2000.
entry(0x2000)

# The bytes from &201e up to &202d run at &0900. Inside the 'with', an
# address that could be in either place means the moved routine, so the
# label goes on its first instruction.
with move(0x900, 0x201e, 0x202d-0x201e):
    label(0x900, "print_and_inc_zp")

# Use all the information provided to actually disassemble the program.
go()
