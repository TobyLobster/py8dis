"""An Acorn Atom program (see asm_to_create_test_binaries/atom_hardware.asm),
disassembled with acorn.atom(): what it writes to the 8255's ports is
commented ('Select graphics mode 4 (256x192, 2 colours)', 'Select keyboard
row 3', 'Toggle the speaker', 'Select colour set 1', 'Set port C bit 2
(speaker high)', 'Set the 8255's modes: ...'), with known values and with
read-modify-writes, and so are its tests of their input bits ('Test the
field sync' for 'bit #B002 : bpl', 'Test the CTRL key' for 'bit #B001 :
bvc' or 'lda #B001 : and #$40', 'Test the 2.4 kHz tape tone input' for
'lda #$10 : bit #B002 : beq', and both bits 7 and 6 for a BIT with no
branch after it)."""

from commands import *
import acorn

load(0x2900, "orig/atom_hardware.orig", "6502", "898362579b82ecfb9f6e9ee135dc0050")
acorn.atom()
entry(0x2900, "start")
go()
