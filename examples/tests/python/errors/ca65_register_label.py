"""A label named after a register, with ca65 output: ca65 doesn't accept
'a', 'x' or 'y' as a label."""

import sys
sys.argv[1:] = ["--ca65"]

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x0070, "x")
entry(0x2000)
go()
