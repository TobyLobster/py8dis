"""A ZX Spectrum program (see asm_to_create_test_binaries/spectrum_test.asm),
with spectrum.spectrum48(), which names the ROM routines and system
variables it uses (including with IY), comments what it prints with RST $10,
follows the calculator's bytecode after RST $28 and the error number after
RST $08, comments what it writes to the border and reads from the
keyboard, and finds the routine it sets as the current channel's output
routine (my_print) and a return address it pushes (resume), but not a value
it pushes then pops (table, which stays data)."""

from commands import *
import spectrum

load(0x8000, "orig/spectrum_test.orig", "z80", "1dd32f5e22abe1f9b0e500432d20d178")
spectrum.spectrum48()

entry(0x8000, "start")
label(0x8076, "message")
expr(0x8012, "message")
expr(0x8015, "message_end - message")
label(0x807c, "message_end")
label(0x806a, "resume")
label(0x806c, "clear_screen")
label(0x8070, "my_print")
label(0x8073, "table")

go()
