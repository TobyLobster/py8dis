"""commodore.pet() with 80 columns and BASIC 2 (only BASIC 4 PETs, the 8000
series, have 80 columns)."""

from commands import *
import commodore

load_prg("orig/pet2_test.orig", "6502")
commodore.pet(basic=2, columns=80)
go()
