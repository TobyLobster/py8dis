"""A C128 program that changes the MMU's configuration (see
asm_to_create_test_binaries/c128_banks_test.asm), with commodore.c128():
each store to the MMU's configuration register is commented with what it
sets (e.g. 'Set the MMU to bank 0 (RAM 0 only)'), and the code after it is
named by that configuration: e.g. after bank 0 is set, 'lda $d020' is RAM,
'ld020', not 'vic_border_colour'; after all RAM with I/O ($3e), 'lda $e000'
is RAM, not the Kernal's reset routine; in bank 1, 'lda $1000' is RAM 1, not
the function key lengths (but $0300 is common RAM, RAM 0, as always). After
'sta $ff01' (preconfiguration A, not known) it's bank 15 again, as
everywhere else. In bank 0, 'jsr $ffd2' calls RAM, 'lffd2', so it isn't
commented as CHROUT (and its 'lda #$41' isn't a character), as it is in bank
15 at the end (with a store to $d019 that acknowledges the VIC-II's raster
interrupt). The routine at &1c5f runs in bank 0 (its caller would set the
MMU in a real program), which c128_bank() says: so its 'lda $d000,x' is RAM,
'ld000', not the VIC-II's 'vic_sprite0_x', its 'sta $4000,x' is RAM, not
BASIC ROM, its 'sta $d020' doesn't store a colour, its 'sta $d019' isn't
commented as acknowledging an interrupt, and its 'jsr $ff7d' isn't
PRIMM, so there's no string after it to skip.

The configuration is followed through the code as it runs: after bank 0 is
set at flow_test, the loop's 'lda $d000,x' is RAM too, and so is 'inc
$d020' in the subroutine only ever called in bank 0; the subroutine called
in bank 15 and in bank 0 isn't known, so it has bank 15's names. After a
call to a subroutine that sets bank 0 itself, 'lda $d020' is RAM; and after
PRIMM in bank 14 (with the Kernal, and the character ROM at $d000), the
code after its string runs in bank 14 too, so 'lda $d020' is the character
ROM."""

from commands import *
import commodore

load_prg("orig/c128_banks_test.orig", "6502", "a1eace66151a6ecad511e56199df70b9")
commodore.c128()
commodore.c128_bank(0x1c5f, 0x1c76, 0)
go()
