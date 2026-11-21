"""load_apple_file() of a file whose name gives a file type without a load
address (TXT)."""

import shutil
from commands import *

shutil.copyfile("orig/helloworld.orig", "build/notes#040000")
load_apple_file("build/notes#040000")
go()
