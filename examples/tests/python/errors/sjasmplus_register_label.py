"""A label named after a register, with sjasmplus output: sjasmplus takes
'hl' in an operand to be the register."""

import sys
sys.argv[1:] = ["--sjasmplus"]

from commands import *

load(0x0000, "orig/trace_z80.orig", "z80")
label(0x0000, "hl")
entry(0x0000)
go()
