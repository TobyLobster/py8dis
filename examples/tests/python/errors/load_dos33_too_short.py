"""load_dos33_binary() of a file too short to be a DOS 3.3 binary file
(just the header)."""

from commands import *

with open("orig/apple_dos33_test.orig", "rb") as f:
    header = f.read(4)
with open("build/too_short.dos33", "wb") as f:
    f.write(header)
load_dos33_binary("build/too_short.dos33")
go()
