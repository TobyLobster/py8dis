"""The BASIC ROM of MEGA65's Open ROMs, a free replacement for the C64's
ROMs (https://github.com/MEGA65/open-roms; see orig/open-roms/README.txt),
with the C64's workspace and Kernal calls but its own code, so the C64's ROM
labels aren't used (rom_labels=False)."""

from commands import *
import commodore

load(0xa000, "orig/open_roms_basic.orig", "6502", "6f0dec43fad06b22d2dbdbc6f2146627")
commodore.c64(rom_labels=False)
commodore.basic_rom()

# The commands' code, in an RTS jump table indexed by the command's token
# (&80-&a6): the low bytes (of the address - 1) at &bd7f and the high bytes at
# &bda6. The commands (END to NEW, &80-&a2) are named by keyword, e.g.
# 'basic_command_print'. (The other tokens, from TAB( to SPC(, aren't
# commands, and go to a syntax error.)
named = set()
for i in range(0xa7 - 0x80):
    rts_code_ptr(0xbd7f + i, 0xbda6 + i)
    target = (memory[0xbda6 + i] << 8 | memory[0xbd7f + i]) + 1
    keyword = commodore.basic_v2_tokens[i].lower().replace("#", "_hash").replace("(", "")
    if i <= 0xa2 - 0x80 and target not in named:
        named.add(target)
        label(target, "basic_command_" + keyword)

# Another RTS jump table: three entries, the low bytes at &bfee and the high
# bytes at &bff1
for i in range(3):
    rts_code_ptr(0xbfee + i, 0xbff1 + i)

go()
