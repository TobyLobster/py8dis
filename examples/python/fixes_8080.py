"""8080 code (see asm_to_create_test_binaries/fixes_8080.asm). RST is
traced as a call, on after it and at the code it calls ('rst_08'; it used
to end the code there), and written with its address ('rst $08', which
z88dk-z80asm takes, rather than 'rst 1'); the code CALL calls is named
'sub_...' (it was 'c...'); 'lxi hl, $0120' has no character comment (it
was ' ', from the low byte), while 'lxi bc, $0041' has 'A'; and the
conditional jump's operand uses its expression (it was ignored)."""

from commands import *

load(0x0000, "orig/fixes_8080.orig", "8080", "2f404383ce92b30a11fe5de27820a3bc")
entry(0x0000, "start")
label(0x001a, "finish")
constant(0x1a, "finish_offset")
expr(0x0015, "start + finish_offset")
go()
