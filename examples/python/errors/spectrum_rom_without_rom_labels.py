"""spectrum.rom() (for the 48K ROM) after spectrum48(rom_labels=False),
which is for a replacement ROM."""

import sys
sys.argv[1:] = ["--z88dk"]

from commands import *
import spectrum

load(0x0000, "orig/spectrum48.orig", "z80")
spectrum.spectrum48(rom_labels=False)
spectrum.rom()
go()
