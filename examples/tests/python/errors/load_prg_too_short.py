"""load_prg() of a file too short to be a PRG file (just a load address)."""

from commands import *

with open("build/too_short.prg", "wb") as f:
    f.write(bytes([0x01, 0x08]))
load_prg("build/too_short.prg", "6502")
go()
