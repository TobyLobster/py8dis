"""Quikman 2K8, a VIC-20 game by Robert Hurst (1984, completed in 2008), for
an unexpanded VIC-20, with commodore.vic20(), which finds the BASIC program,
the IRQ handler the game sets, and the Kernal, VIC and VIA addresses it uses.
The game's own variables are named here from its source (see
orig/quikman2k8/README.txt), since it uses zero page and &02a1-&02e6 for its
own purposes."""

from commands import *
import commodore

load_prg("orig/quikman2k8.orig", "6502", "1f62bcfd9f8064437e63d8917eb38454")
commodore.vic20()

# The game's variables, from its source
label(0x10, "ppilltimer")       # powerpill effectiveness timer
label(0x39, "fruittimer")
label(0x3a, "fruitflag")
label(0x3b, "ppillflag")
label(0x3c, "chomp")
label(0x3d, "chewing")
label(0x3e, "digit")
label(0x3f, "points")
label(0x40, "olddir")
label(0x41, "newdir")
label(0x42, "joyval")
label(0x43, "qmandir")
label(0x44, "frame")
label(0x45, "lives")
label(0x46, "flashpill")
label(0x47, "extraqman")
label(0x48, "demoqman")
label(0x49, "fruitlevel")
label(0x4a, "dots")
label(0x4b, "penalty")
label(0x61, "monmove")
label(0x70, "fleeingscore")
label(0x02a1, "sprite")         # the game's sprite registers
label(0x02a2, "spritex")
label(0x02a3, "spritey")
label(0x02b2, "spriteclr")
label(0x02ba, "spriteimg1")
label(0x02c2, "spriteimg2")
label(0x02cc, "spritelast")
label(0x02dd, "saveback")
go()
