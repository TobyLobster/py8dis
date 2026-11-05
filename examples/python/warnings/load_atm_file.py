"""load() of a file named .atm, which warns that load_atm() would leave out
its 22-byte header. (It's loaded 22 bytes early, so the program itself is
at the right address.)"""

import shutil
from commands import *

shutil.copyfile("orig/atm_test.orig", "build/load_atm_file.atm")
load(0x28ea, "build/load_atm_file.atm", "6502")
entry(0x2906)
go()
