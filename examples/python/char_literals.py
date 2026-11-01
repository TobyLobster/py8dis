"""Character literals (see asm_to_create_test_binaries/char_literals.asm): the
program is 'lda #0' to 'lda #255', and char() marks each immediate value as
a character. This tests how each assembler writes every character as a
literal (e.g. 'A'), including quotes and backslashes, which each writes in
its own way, and that a value that isn't a printable character, or that the
assembler can't write as a literal, stays a number."""

from commands import *

# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are
# multiple versions of the same program.
load(0x2000, "orig/char_literals.orig", "6502")

# (The test is a run of loads, all but the last of them redundant, so don't
# comment them)
config.set_redundant_instruction_comments(False)

# Start tracing instructions at 0x2000.
entry(0x2000)

# The operand of each 'lda #n' (two bytes each, so every other byte)
for i in range(0,256):
    char(0x2001 + 2*i)

# Use all the information provided to actually disassemble the program.
go()
