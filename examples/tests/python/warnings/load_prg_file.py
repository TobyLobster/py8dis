"""load() of a file named .prg, which warns that load_prg() would leave out
its two-byte header. (It's loaded two bytes early, so the program itself is
at the right address, as some people do.)"""

import shutil
from commands import *

shutil.copyfile("orig/prg_test.orig", "build/load_prg_file.prg")
load(0x07ff, "build/load_prg_file.prg", "6502")
entry(0x080d)
go()
