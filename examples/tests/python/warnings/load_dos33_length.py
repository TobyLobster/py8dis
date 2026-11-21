"""load_dos33_binary() of a DOS 3.3 binary file with more data after the
header than the header's length (as when a tool extracts whole sectors),
which warns (the data is all loaded)."""

from commands import *

with open("orig/apple_dos33_test.orig", "rb") as f:
    data = f.read()
with open("build/load_dos33_length.dos33", "wb") as f:
    f.write(data + bytes(11))
load_dos33_binary("build/load_dos33_length.dos33")
entry(0x6000)
go()
