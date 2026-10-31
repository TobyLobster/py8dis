"""What's known about the registers after a BNE that isn't taken (see
asm_to_create_test_binaries/branch_state.asm), shown after each instruction:
Z is set, so the result that set it was 0 (e.g. Y after DEY), or the
register compared with an immediate value was equal to it (e.g. A after CMP
#$7b). A branch to the next instruction says nothing."""

from commands import *

load(0x2000, "orig/branch_state.orig", "6502", "a7766739b42400021017b2a4eaf685ba")
entry(0x2000, "start")

config.set_show_cpu_state(True)

go()
