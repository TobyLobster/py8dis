"""load_apple_file() of an AppleDouble header file, which has no data."""

from commands import *

with open("build/appledouble.as", "wb") as f:
    f.write(bytes.fromhex("00051607 00020000") + bytes(18))
load_apple_file("build/appledouble.as")
go()
