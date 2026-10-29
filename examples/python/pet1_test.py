"""The PET program in asm_to_create_test_binaries/pet_test.asm, made for
BASIC 1 (the original 1977 ROMs, with the IRQ vector at &0219 and the
Kernal's IRQ handler at &e685), disassembled with commodore.pet(basic=1,
names="commodore"), so with the names in Commodore's source (e.g. 'cinv',
'ndx')."""

from commands import *
import commodore

load_prg("orig/pet1_test.orig", "6502", "9438e99030deae2ad5316653646d0086")
commodore.pet(basic=1, names="commodore")
go()
