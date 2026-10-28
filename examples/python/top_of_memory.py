"""Code at the top of memory (see asm_to_create_test_binaries/top_of_memory.asm).
These used to crash py8dis:
- the branch at &ffe2 wraps round to &0020 (shown as 'bmi l0020', since acme
  and xa wrap a branch's target as the 6502 does, and for beebasm, which
  doesn't, as 'bmi P%+62');
- the code that runs up to &ffff, after which tracing stops (rather than
  carrying on at &0000);
- the entry point at &fffe, inside that instruction, is the start of a
  three byte instruction that would run past the top of memory, so it isn't
  one."""

from commands import *

load(0xffe0, "orig/top_of_memory.orig", "6502", "330856f6a6272f61f8224a916847a259")
entry(0xffe0, "start")
entry(0xfffe)
go()
