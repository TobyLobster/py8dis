"""Classifying bytes that have already been classified."""

from commands import *

load(0x2000, "orig/helloworld.orig", "6502")
string(0x200e)
byte(0x2010)
go()
