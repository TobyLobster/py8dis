"""The Kernal ROM of MEGA65's Open ROMs, a free replacement for the C64's
ROMs (https://github.com/MEGA65/open-roms; see orig/open-roms/README.txt).
It has the C64 Kernal's jump table, vectors and workspace, but its own code,
so the C64's ROM labels aren't used (rom_labels=False)."""

from commands import *
import commodore

load(0xe000, "orig/open_roms_kernal.orig", "6502", "a0b97c34758e9f4af03cb4476166b1d8")
commodore.c64(rom_labels=False)
commodore.kernal_rom()

# The default vectors, which RESTOR copies to &0314-&0333 (at the same
# address as in the C64's Kernal)
label(0xfd30, "default_vectors")
for i, handler in enumerate(["irq", "brk", "nmi", "open", "close", "chkin", "chkout", "clrchn",
                             "chrin", "chrout", "stop", "getin", "clall", "user_command", "load", "save"]):
    code_ptr(0xfd30 + 2*i, label_name="default_%s_handler" % handler)

# The screen editor's control codes: the code at &fdee compares the character
# with each of the 17 codes at &ec4c (X from 16 down to 0), and jumps to the
# code's routine with an RTS: the addresses minus 1, the low bytes at &ec5d
# and the high bytes at &ec6e. (py8dis can't mark the table itself, since it
# doesn't know that the loop's DEX stops at 0.)
label(0xec4c, "control_codes")
label(0xec5d, "control_code_routines_low")
label(0xec6e, "control_code_routines_high")
for i in range(17):
    rts_code_ptr(0xec5d + i, 0xec6e + i)

go()
