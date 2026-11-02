"""65C02 cycle counts, shown with config.set_show_cycles(True) (see
asm_to_create_test_binaries/cycles_65c02.asm): ADC and SBC take an extra
cycle in decimal mode, in every addressing mode, and an absolute indexed
BIT or shift an extra cycle if indexing crosses a page."""

from commands import *
import config

config.set_show_cycles(True)

load(0x2000, "orig/cycles_65c02.orig", "65c02", "85a02d73645ae17ca6e02281e5a7a61a")
entry(0x2000, "start")
go()
