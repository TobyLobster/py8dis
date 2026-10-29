"""The PET program in asm_to_create_test_binaries/pet_test.asm, made for
BASIC 2 (with its workspace and ROM addresses, e.g. the IRQ vector at &0090
and the Kernal's IRQ handler at &e62e), disassembled with
commodore.pet(basic=2)."""

from commands import *
import commodore

load_prg("orig/pet2_test.orig", "6502", "f85fad64c4756c566923f51d242b534a")
commodore.pet(basic=2)
go()
