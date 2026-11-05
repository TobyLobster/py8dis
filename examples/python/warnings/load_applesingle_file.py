"""load() of an AppleSingle file from its start, which warns that
load_apple_file() would leave out its header. (It's loaded at the header's
address, so the program itself is at the right address.)"""

import shutil
from commands import *

shutil.copyfile("orig/apple_applesingle_test.orig", "build/load_applesingle_file")
load(0x07b8, "build/load_applesingle_file", "6502")
entry(0x0803)
go()
