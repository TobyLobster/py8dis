"""A label named after an operator, with sjasmplus output: sjasmplus takes
'low' (in any case) to be its low byte operator."""

import sys
sys.argv[1:] = ["--sjasmplus"]

from commands import *

load(0x0000, "orig/trace_z80.orig", "z80")
label(0x0000, "LOW")
entry(0x0000)
go()
