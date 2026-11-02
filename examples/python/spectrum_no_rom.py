"""A ZX Spectrum program (see asm_to_create_test_binaries/spectrum_no_rom.asm),
with spectrum.spectrum48(rom_labels=False), as for a replacement ROM: (IY+d)
is written as an offset from ERR_NR's address unless either half of IY is
known to be something else, and a call to $335E, which is GEN-ENT-1 only in
Sinclair's ROM, is followed by code, not the calculator's bytecode."""

from commands import *
import spectrum

load(0x8000, "orig/spectrum_no_rom.orig", "z80", "424bd3b003f8926635d9210ca8a0eda9")
spectrum.spectrum48(rom_labels=False)

entry(0x8000, "start")

go()
