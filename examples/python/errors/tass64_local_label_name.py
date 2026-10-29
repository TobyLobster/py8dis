"""A label starting with '_', with 64tass output: 64tass takes it to be a
'cheap local' label, which can't be used after the next label."""

import sys
sys.argv[1:] = ["--64tass"]

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
label(0x0070, "_count")
entry(0x2000)
go()
