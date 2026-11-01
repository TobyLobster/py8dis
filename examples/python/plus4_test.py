"""A Plus/4 program (a PRG file with a BASIC SYS line), with commodore.plus4().
(Made from asm_to_create_test_binaries/plus4_test.asm.)

The program prints with PRIMM and CHROUT, uses the TED (the colours, sound,
the keyboard latch and the ROM switch), the screen and its colour RAM and
the ACIA, and sets the IRQ vector. plus4() names and comments all of these,
so the control file needs no commands of its own."""

from commands import *
import commodore

load_prg("orig/plus4_test.orig", "6502", "212114c931d195facc29ebb2c7a39123")
commodore.plus4()
go()
