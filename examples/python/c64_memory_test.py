"""A C64 program that switches the ROMs and the I/O out and in with the
6510's port at $01 (see asm_to_create_test_binaries/c64_memory_test.asm),
disassembled with commodore.c64(), which comments the stores to $01 and
follows the configuration through the code, naming the addresses the code
uses as what they are in that configuration (e.g. RAM rather than I/O, so
'ld020' rather than 'vic_border_colour'). A routine whose configuration
isn't known from the code is given one with c64_configuration()."""

from commands import *
import commodore

load_prg("orig/c64_memory_test.orig", "6510", "fb51374b06213bb1446a9ccda4403a56")
commodore.c64()

# Called with the Kernal and BASIC switched out ($35), by code that isn't in
# the program
entry(0x085f, "kernal_out_routine_entry")
commodore.c64_configuration(0x085f, 0x0863, 0x35)

go()
