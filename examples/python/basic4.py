"""BBC BASIC 4, the BASIC ROM for the BBC Master, a sideways ROM with 65C02
code, as a test on a large real program. It's mostly left to py8dis: it
uses acorn.master() and acorn.is_sideways_rom(), a table of routine
addresses traced with wordentry(), and a label maker hook that names one
label."""

from commands import *
import acorn

load(0x8000, "orig/basic4.orig", "65c02", "e11eed95d1caba8aa9772e9001590585")
#set_output_filename("basic4.rom")

# Add labels specific to the Master
acorn.master()

# This is a sideways ROM, so it has a header and standard entry points we can label.
acorn.is_sideways_rom()

# A table of the addresses of routines, which tracing doesn't find by itself
wordentry(0x8826, 117) # XXX: table size is a guess

# As an example, label maker can change the label name referenced at a given address
# (But in this case a local_label() could be used instead)
def our_label_maker(d):
    """Name the label used by the instruction at &80bd (the branch back to the
    start of its loop) 'copy_to_stack_loop'."""
    if d.binary_addr == 0x80bd:
        d.name="copy_to_stack_loop"

set_label_maker_hook(our_label_maker)

# ENHANCE: Add a brk() hook? This would allow us to disassemble OS
# errors without letting autostring() do it - it's not a big deal, but
# it can interpret error codes as ASCII.

go()
