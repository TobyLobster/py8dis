"""load_atm() of an ATM file whose header gives a length that isn't the
length of the data after it, which warns (the data is all loaded)."""

from commands import *

with open("orig/atm_test.orig", "rb") as f:
    data = f.read(30)
with open("build/load_atm_length.atm", "wb") as f:
    f.write(data)
load_atm("build/load_atm_length.atm", "6502")
go()
