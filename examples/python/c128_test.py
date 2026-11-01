"""A C128 program (a PRG file with a BASIC SYS line), with commodore.c128().
(Made from asm_to_create_test_binaries/c128_test.asm.)

The program prints with PRIMM (whose inline string is marked, and skipped
when tracing), uses the MMU, the VDC, the VIC-II and the C128's workspace,
sets the IRQ vector, calls routines in other banks with JSRFAR and JMPFAR,
and loads a file into bank 1. c128() names and comments all of these, so the
control file needs no commands of its own."""

from commands import *
import commodore

load_prg("orig/c128_test.orig", "6502", "f33285af69217592a591a79fb0ef275a")
commodore.c128()
go()
