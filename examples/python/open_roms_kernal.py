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

go()
