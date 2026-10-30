"""Tracing Z80 code (see asm_to_create_test_binaries/trace_z80.asm): RST
(with a hook for RST $08, which is followed by a data byte; the code RST $10
calls is named rst_10), JP (IX), JR and DJNZ, relative jumps that wrap round
the top and bottom of memory, code copied elsewhere to run (move(), written
as PHASE and DEPHASE), and expressions for an index register's displacement,
an immediate value and a port."""

from commands import *

load(0x0000, "orig/trace_z80.orig", "z80", "ed5e5d61eb9bb80fe2eaa9a4f315f5cf")

# The routine copied to &8000, and the code copied to the top of memory
move(0x8000, 0x0050, 7)
move(0xfff8, 0x005d, 8)

constant(3, "count")
constant(0xfe, "ula_port", format=Format.HEX)
constant(0x8000, "copy_to", format=Format.HEX)

def error_hook(target, caller):
    """RST $08 is followed by an error number: the code continues after it."""
    byte(caller + 1)
    comment(caller + 1, "error number", inline=True)
    return caller + 2

entry(0x0000, "start")
hook_subroutine(0x0008, "error", error_hook)
label(0x0018, "report")
entry(0x004b, "done")           # (reached by the jump to ret from the routine)
label(0x004d, "finish")
label(0x8000, "routine")
label(0xfff8, "top")
label(0x001d, "main")
label(0x0057, "last_error")
label(0x0059, "variables")
label(0x005d, "top_source")
byte(0x0057, 2)
byte(0x0059, 4)
label(0xfffe, "last")

expr(0x0011, "ula_port")        # out (ula_port),a
expr(0x0024, "(count+1)*2")     # ld b,(count+1)*2
expr(0x0028, "ula_port")        # in a,(ula_port)
expr(0x002b, "variables")       # ld ix,variables
expr(0x002f, "count")           # ld a,(ix+count)
expr(0x0034, "routine_source")  # ld hl,routine_source
expr(0x0037, "copy_to")         # ld de,copy_to
expr(0x003a, "routine_end - routine_source")
expr(0x0042, "done")            # ld hl,done
expr(0x0047, "finish")          # ld ix,finish
label(0x0050, "routine_source")
label(0x0057, "routine_end")

config.set_show_cycles(True)

go()
