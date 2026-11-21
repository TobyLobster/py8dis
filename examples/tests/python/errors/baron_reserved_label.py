"""A label named after one of Baron's constants (TRUE, FALSE and PI, in any
case), which it doesn't accept as a label."""

import sys
sys.argv[1:] = ["--baron"]

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x0070, "pi")
entry(0x2000)
go()
