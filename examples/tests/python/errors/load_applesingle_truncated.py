"""load_apple_file() of an AppleSingle file cut short in its list of
entries."""

from commands import *

with open("orig/apple_applesingle_test.orig", "rb") as f:
    data = f.read(40)
with open("build/truncated.as", "wb") as f:
    f.write(data)
load_apple_file("build/truncated.as")
go()
