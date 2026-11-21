"""local_label(): zero page &70 is 'char_to_print' everywhere except in the
bit counting loop (&2017-&2021), where the code reuses it, and it's
'bit_value'. The program also has a CRTC register number stored to the
CRTC's address register, which acorn.bbc() names (crtc_vert_total_adjust),
and a subroutine header."""

from commands import *
import config
import acorn

config.set_label_references(False)

# One list of memory locations at the top, without the headings for each
# memory region
config.set_memory_region_headings(False)



# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are
# multiple versions of the same program.
load(0x2000, "orig/local_labels.orig", "6502", "ac64dbf0050be82f97f01b22262406a8")

# Add labels specific to the BBC Micro
acorn.bbc()

# Start tracing instructions at 0x2000.
entry(0x2000)
subroutine(0x2000, "test_for_local_labels",
    "Local Labels Test",
    "This is just a jumble of code to test: the local labels feature, CRTC register substitution, and subroutine headers. It outputs some characters then reuses a variable to count some bits. It doesn't really make sense as a program in its own right. It also shows the subroutine header.",
    on_entry={'a': "(ignored)", 'x': "(ignored)"},
    on_exit={'x': "Holds the number of bits set.", 'y': "(preserved)"} )
comment(0x2004, "output some characters")
label(0x2006, "print_loop")
char(0x2007)
blank(0x2015)
comment(0x2015, "count bits in a byte")
label(0x2019, "bit_counting_loop")
label(0x201e, "skip_add_to_bit_count")
label(0x2026, "crtc_substitution_test")

# TEST LOCAL LABELS:
# &70 is char_to_print, except where it's used in the code from &2017 up to
# (but not including) &2022, where it's bit_value

label(0x70, "char_to_print")
local_label(0x70, "bit_value", 0x2017, 0x2022)


# Use all the information provided to actually disassemble the program.
go()
