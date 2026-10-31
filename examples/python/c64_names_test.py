"""c64_test's program, with commodore.c64(names="commodore"): the names in
Commodore's documentation, in capitals (e.g. 'EXTCOL' rather than
'vic_border_colour'). The program's byte for the key pressed is named 'key',
which is also Commodore's name for the IRQ handler at &ea31, 'KEY', so that
isn't used for &ea31 (an optional label's name isn't used if it's another
address's, in any case, since some assemblers, e.g. 64tass, take 'key' and
'KEY' to be the same)."""

from commands import *
import commodore

load_prg("orig/c64_names_test.orig", "6510", "edfe1298d5cffb5b0c85432f3b17f40f")
commodore.c64(names="commodore")
label(0x0964, "key")
go()
