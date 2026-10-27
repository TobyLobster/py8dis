"""A PC64 P00 file (a 26 byte header, then a PRG file), loaded with
load_prg(). As for prg_test, the output assembles to the PRG file (without
the P00 header). (Made by asm_to_create_test_binaries/go.)"""

from commands import *

start = load_prg("orig/p00_test.p00", "6502", "2759154d1c3724cc7a3be208033cb8d8")
assert start == 0x0801

label(0xffd2, "chrout")
entry(0x080d, "start")
go()
