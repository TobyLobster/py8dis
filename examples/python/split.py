"""Two files disassembled together, with a load() for each: the same program
as move.py, but with the routine already at &0900 in a file of its own
(orig/split1.orig), and the main program at &2000 (orig/split2.orig). The
routine is traced from the main program's call to it. The output assembles
to both files' contents, at their addresses, with zeroes in the gap between
them (orig/split.orig). (Here acorn.bbc() comes before the load()s, which
works too.)"""

from commands import *
import acorn

# Add labels specific to the BBC Micro
acorn.bbc()

# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are multiple versions
# of the same program.
load(0x900, "orig/split1.orig", "6502", "e0b4f3dc330f1703fe3eff2557f1cf34")
load(0x2000, "orig/split2.orig", "6502", "7e0ece611bcf58bf310ae3b7d8820631")

# Start tracing instructions at 0x2000.
entry(0x2000)

label(0x900, "print_and_inc_zp")

# Use all the information provided to actually disassemble the program.
go()
