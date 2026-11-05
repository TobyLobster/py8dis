"""The Apple II test program (asm_to_create_test_binaries/apple2_test.asm,
copied by the go script) as a IIe program, with apple.apple2(model="iie",
names="descriptive"): py8dis's own names (e.g. 'print_char' for COUT,
'output_hook' for CSWL), and the IIe's AUXMOVE (aux_move) and status switch
(is_not_vertical_blank) named too."""

from commands import *
import apple

load(0x0803, "orig/apple2e_names_test.orig", "6502", "f9ffa936d54ad7c86175faba49305b06")
apple.apple2(model="iie", names="descriptive")
entry(0x0803, "start")
go()
