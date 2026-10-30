"""A label named after an instruction, with ca65 output, for the "6510"
CPU: ca65 doesn't accept a mnemonic of the CPU (here, with '.setcpu
"6502X"', the undocumented LAX) as a label."""

import sys
sys.argv[1:] = ["--ca65"]

from commands import *

load(0x2000, "orig/helloworld.orig", "6510")
label(0x0070, "lax")
entry(0x2000)
go()
