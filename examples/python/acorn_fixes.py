"""A BBC Micro program (made from asm_to_create_test_binaries/acorn_fixes.asm)
with things acorn.bbc() used to comment wrongly or not at all: VDU 31 (move
the text cursor), whose column comes from X and whose row is what A still
holds after X has changed (so the row isn't X), and a table of the
character rows' offsets from the start of the screen as words (it's
commented)."""

from commands import *
import acorn

load(0x2000, "orig/acorn_fixes.orig", "6502", "07a10f02bf6c33318356098c639f0227")
acorn.bbc()
entry(0x2000, "start")
go()
