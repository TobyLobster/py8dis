"""cpm.cpm() for a 6502 program (CP/M programs are Z80 or 8080 code)."""

from commands import *
import cpm

load(0x2000, "orig/helloworld.orig", "6502")
cpm.cpm()
go()
