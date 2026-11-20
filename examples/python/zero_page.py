"""What py8dis knows about zero page (see
asm_to_create_test_binaries/zero_page.asm): bytes stored there are known
when they're loaded again, used by AND or CMP, or changed by INC, DEC or
ASL, so a branch can be always taken because of them; a store indexed by a
known X writes one byte, and by an unknown X could write any; a mask kept
in zero page sizes a table, as does a pointer there for '(ptr),y'; a loop
clearing memory through a known pointer names the buffer; the loads that
set a pointer are written as the low and high bytes of where it points;
a loop waiting
for an interrupt to change a byte isn't taken to wait forever; what's known
survives a call to a subroutine that doesn't write the byte; and a byte in
I/O isn't tracked."""

from commands import *

load(0x2000, "orig/zero_page.orig", "6502", "b81df58768738f514c28eb481693b4fc")
entry(0x2000, "start")
label(0x0400, "buffer")
io_range(0x7e, 0x7f)

go()
