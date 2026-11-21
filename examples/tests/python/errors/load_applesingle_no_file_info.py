"""load_apple_file() of an AppleSingle file without ProDOS file
information, so its load address isn't known: a header with one entry, the
data fork."""

from commands import *

with open("orig/helloworld.orig", "rb") as f:
    data = f.read()
header = bytes.fromhex("00051600 00020000") + bytes(16) + (1).to_bytes(2, "big")
header += (1).to_bytes(4, "big") + (38).to_bytes(4, "big") + len(data).to_bytes(4, "big")
with open("build/no_file_info.as", "wb") as f:
    f.write(header + data)
load_apple_file("build/no_file_info.as")
go()
