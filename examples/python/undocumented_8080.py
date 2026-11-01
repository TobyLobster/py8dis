"""The 8080's undocumented opcodes (see
asm_to_create_test_binaries/undocumented_8080.asm).

&08, &10, &18, &20, &28, &30 and &38 run as NOP, &CB as JMP, &D9 as RET, and
&DD, &ED and &FD as CALL. They're traced as what they run as (so the calls
and the jump are followed), and output as data bytes with the instruction in
a comment. (A regression test: written as 'nop', which assembles to &00, or
as the 8085's 'rim' and 'sim', for &20 and &30, they wouldn't reassemble to
the original bytes.) The cycles and what's known about the registers are
shown too."""

from commands import *

load(0x0100, "orig/undocumented_8080.orig", "8080", "54a257bce166e4ed0ec2bb0d3fb7039d")
entry(0x0100)

label(0x0115, "subroutine")
label(0x0117, "finish")

config.set_show_cycles(True)
config.set_show_cpu_state(True)

go()
