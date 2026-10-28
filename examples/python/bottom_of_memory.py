"""Code at the bottom of memory (see asm_to_create_test_binaries/bottom_of_memory.asm):
the branch at &0002 wraps round below &0000 to &fff2, as on the 6502. This
used to fail with an assertion. It's shown as 'bmi lfff2' for acme and xa,
which wrap a branch's target too, and as 'bmi P%-16' for beebasm, which
doesn't."""

from commands import *

load(0x0000, "orig/bottom_of_memory.orig", "6502", "bfd7c2b6c9c548b89af730ded79c2b9a")
entry(0x0000, "start")
go()
