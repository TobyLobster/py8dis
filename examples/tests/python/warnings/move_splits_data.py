"""A move() whose boundary, at &3002, is in the middle of data the control
file classified (four bytes from &3000), which warns that it's split. (The
bytes py8dis classifies itself, the ones left over, are split without a
warning, as in moving1.)"""

from commands import *

load(0x3000, "orig/moving1.orig", "6502")
move(0x3001, 0x3002, 255)
byte(0x3000, 4)
go()
