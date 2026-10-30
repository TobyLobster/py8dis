"""A ZX Spectrum program (see asm_to_create_test_binaries/spectrum_test.asm),
with spectrum.spectrum48(), which names the ROM routines and system
variables it uses (including with IY), comments what it prints with RST $10,
follows the calculator's bytecode after RST $28 and the error number after
RST $08, and comments what it writes to the border and reads from the
keyboard."""

from commands import *
import spectrum

load(0x8000, "orig/spectrum_test.orig", "z80", "66077f54f6841ae2d20cc4e9da356dc1")
spectrum.spectrum48()

entry(0x8000, "start")
label(0x8054, "message")
expr(0x8012, "message")
expr(0x8015, "message_end - message")
label(0x805a, "message_end")

go()
