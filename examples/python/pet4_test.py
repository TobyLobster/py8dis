"""A PET program (a PRG file with a BASIC program that SYSes to the machine
code), made from asm_to_create_test_binaries/pet_test.asm for BASIC 4 with
80 columns, disassembled with commodore.pet(basic=4, columns=80): the BASIC
lines (with BASIC 4's CATALOG), CHROUT, GETIN, STOP and CLRCHN, BASIC's
STROUT and LINPRT, the IRQ vector at &0090 and the handler, which ends at the
Kernal's IRQ handler (&e455), the VIA, a PIA, the CRTC, the screen and the
workspace."""

from commands import *
import commodore

load_prg("orig/pet4_test.orig", "6502", "8f7d50fdbedeb165b312eac42f8786f3")
commodore.pet(basic=4, columns=80)
go()
