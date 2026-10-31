"""An 8080 CP/M program (see asm_to_create_test_binaries/cpm_8080.asm), a test
of cpm.cpm(): calls to the BDOS commented, their function numbers named, and
page zero's names, with a routine of the program's own that calls the BDOS
with the function number in A."""

from commands import *
import cpm

load(0x0100, "orig/cpm_8080.orig", "8080", "0174f1ac12660c03af1a74c163eb127f")
cpm.cpm()

entry(0x0100)
# A routine that calls the BDOS with the function number in A
label(0x015a, "file")
cpm.bdos_wrapper(0x015a, "a")

go()
