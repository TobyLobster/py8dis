"""A C128 program that changes the MMU's configuration (see
asm_to_create_test_binaries/c128_banks_test.asm), with commodore.c128():
each store to the MMU's configuration register is commented with what it
sets (e.g. 'Set the MMU to bank 0 (RAM 0 only)'), and the code after it is
named by that configuration: e.g. after bank 0 is set, 'lda $d020' is RAM,
'ld020', not 'vic_border_colour'; after all RAM with I/O ($3e), 'lda $e000'
is RAM, not the Kernal's reset routine; in bank 1, 'lda $1000' is RAM 1, not
the function key lengths (but $0300 is common RAM, RAM 0, as always). After
'sta $ff01' (preconfiguration A, not known) it's bank 15 again, as
everywhere else. The routine at &1c4e runs
in bank 0 (its caller would set the MMU in a real program), which
c128_bank() says: so its 'lda $d000,x' is RAM, 'ld000', not the VIC-II's
'vic_sprite0_x', and its 'sta $4000,x' is RAM, not BASIC ROM."""

from commands import *
import commodore

load_prg("orig/c128_banks_test.orig", "6502", "7508ec69723fcb13d2c6c0fd19b6c05d")
commodore.c128()
commodore.c128_bank(0x1c4e, 0x1c5a, 0)
go()
