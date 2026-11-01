"""The smallest 8080 test: the example code from Wikipedia's Intel 8080 page,
a routine that copies BC bytes from (DE) to (HL), with a call before it. A
control file needs nothing more than load() with the CPU "8080", an entry
point and go(): py8dis traces the rest, and makes up the labels."""

from commands import *

# Example code from https://en.wikipedia.org/wiki/Intel_8080#Example_code
load(0x1000, "orig/example8080.orig", "8080")
entry(0x1000)

go()
