"""Comments from what's known about the registers and flags (see
asm/known_state_comments.asm), shown after each
instruction too: carry is set after a CMP and a BNE that isn't taken, so
ADC #3 adds 4; Y is 0 after INY and a BNE that isn't taken, so TYA makes A
0; and carry is set after a BCC that isn't taken, so ROR rotates in a set
bit and ROL rotates it out again.

Then what's known bit by bit: the bits AND, ORA and the shifts make known,
what a BEQ, BPL or BMI that isn't taken says about the register that set
the flag, what a compare says about a register with some bits known, ADC
with D clear, and the comments a rotate or shift gets for the carry (which
it only gets for the bit shifted out if something reads the carry afterwards)."""

from commands import *

load(0x2000, "orig/known_state_comments.orig", "6502", "11daa5b15ada6cc3ffc503f33259d356")
entry(0x2000, "start")
# (The code after the first RTS, which shows what's known bit by bit)
entry(0x201d, "bits")

config.set_show_cpu_state(True)

config.set_label_references(True)
go()
