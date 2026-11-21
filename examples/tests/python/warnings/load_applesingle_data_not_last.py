"""load_apple_file() of an AppleSingle file whose ProDOS file information
comes after its data fork, so the output can't be the header then the
data, which warns (the data fork is loaded on its own)."""

from commands import *

with open("orig/helloworld.orig", "rb") as f:
    data = f.read()
header = bytes.fromhex("00051600 00020000") + bytes(16) + (2).to_bytes(2, "big")
header += (1).to_bytes(4, "big") + (50).to_bytes(4, "big") + len(data).to_bytes(4, "big")
header += (11).to_bytes(4, "big") + (50 + len(data)).to_bytes(4, "big") + (8).to_bytes(4, "big")
file_info = bytes.fromhex("00c3 0006 00002000")
with open("build/data_not_last.as", "wb") as f:
    f.write(header + data + file_info)
load_apple_file("build/data_not_last.as")
entry(0x2000)
go()
