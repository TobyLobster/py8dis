"""load() whose md5sum doesn't match the file."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502", "0123456789abcdef0123456789abcdef")
go()
