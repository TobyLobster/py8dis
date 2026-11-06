"""A label named after a register, with Merlin 32 output: Merlin 32 doesn't
accept 'a', 'x' or 'y' as a label ('x' and 'y' would replace the index
register in e.g. 'lda table,y')."""

import sys
sys.argv[1:] = ["--merlin32"]

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x0070, "y")
entry(0x2000)
go()
