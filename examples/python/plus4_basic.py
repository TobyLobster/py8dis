"""A Plus/4 program (see asm_to_create_test_binaries/plus4_basic.asm),
disassembled with commodore.plus4(): its BASIC program is listed with BASIC
3.5's keywords (GRAPHIC and RLUM; these were '{$de}' and '{$ce}')."""

from commands import *
import commodore

load_prg("orig/plus4_basic.orig", "6502", "f088868ccb7a0afb7dd1c83eed23bad9")
commodore.plus4()
go()
