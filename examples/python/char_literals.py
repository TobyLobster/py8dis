from commands import *

# Load the program to be disassembled into the debugger's memory.
# The md5sum is optional but helps avoid confusion if there are
# multiple versions of the same program.
load(0x2000, "orig/char_literals.orig", "6502")

# (The test is a run of loads, all but the last of them redundant, so don't
# comment them)
config.set_redundant_instruction_comments(False)

# Start tracing instructions at 0x2000.
entry(0x2000)

for i in range(0,256):
    char(0x2001 + 2*i)

# Use all the information provided to actually disassemble the program.
go()
