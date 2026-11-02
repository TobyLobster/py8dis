"""A C128 program (see asm_to_create_test_binaries/c128_fixes.asm),
disassembled with commodore.c128(): its BASIC program is listed with BASIC
7.0's keywords, including the two-byte ones (BANK, FAST and XOR; these were
'{$fe}' etc.), and an MMU configuration with bit 0 set and the internal
function ROM at $c000-$ffff is described without the character ROM, since
$d000-$dfff is the function ROM then."""

from commands import *
import commodore

load_prg("orig/c128_fixes.orig", "6502", "837177a34f96153121d3bf55909df025")
commodore.c128()
go()
