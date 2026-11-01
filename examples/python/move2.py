"""Two routines copied to overlapping places to run: one from &2010 to &0900,
the other from &2029 to &0901. Each move() returns a move ID, and the
commands in a 'with' block for it refer to that move's copy, so each routine
gets its own labels, at addresses the other one has too. The 'jmp &090d' at
the end of the first routine goes to the second one's &090d (in the first,
it's the middle of an instruction), so &090d is a nonentry() in the first
move and an entry() in the second. (move2_legacy_label_maker.py is the same
program, with a label maker hook.)"""

from commands import *

# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are multiple versions
# of the same program.
load(0x2000, "orig/move2.orig", "6502", "6d6fe001ff974fdc798c4f6c2d75c349")

# Start tracing instructions at 0x2000.
entry(0x2000)

# The first routine, &2010-&2021, runs at &0900
low_a_move_id = move(0x900, 0x2010, 0x2022-0x2010)
with low_a_move_id:
    label(0x900, "low_a")
    # Don't trace this routine's copy of &090d (the jump there is to the
    # other routine's)
    nonentry(0x90d)
# The second routine, &2029-&2038, runs at &0901
low_b_move_id = move(0x901, 0x2029, 0x2039-0x2029)
with low_b_move_id:
    entry(0x901, "low_b")
    entry(0x90d, "low_b_baz")

# Use all the information provided to actually disassemble the program.
go()
