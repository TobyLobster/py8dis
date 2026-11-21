"""load_atm() of a file too short to be an ATM file (just the header)."""

from commands import *

with open("orig/atm_test.orig", "rb") as f:
    header = f.read(22)
with open("build/too_short.atm", "wb") as f:
    f.write(header)
load_atm("build/too_short.atm", "6502")
go()
