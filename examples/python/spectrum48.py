"""The ZX Spectrum 48K ROM (see orig/spectrum48/README.txt), a test of the Z80
on a real program, with spectrum.spectrum48() and spectrum.rom(), which name
its routines and system variables, follow the data after RST $08 (an error
number) and RST $28 (the floating point calculator's bytecode), and trace
its tables of routines."""

from commands import *
import spectrum

load(0x0000, "orig/spectrum48.orig", "z80", "4c42a2f075212361c3117015b107ff68")
spectrum.spectrum48()
spectrum.rom()

config.set_show_cycles(True)

go()
