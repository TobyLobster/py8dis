"""A real card's ROM: the drive firmware of Terence Boldt's Apple2-IO-RPi for
slot 7 (MIT licence; see orig/apple2_io_rpi/README.txt), loaded at $C700,
with apple.slot_rom(7). It's a ProDOS block device that the Autostart ROM
boots: slot_rom() describes its ID bytes, marks its number of blocks and
status byte, traces its ProDOS driver from $C7FF, and names ProDOS's
parameters in zero page ('driver_command' etc.) and the slot's I/O
('slot_7_io+7' etc.).

The names are the source's (DriveFirmware.asm), given before slot_rom(), so
that it keeps them (e.g. 'DriverEntry', not 'prodos_driver'). The firmware
has the offsets of Pascal routines at $C70D-$C710, but not Pascal 1.1's ID
bytes, so slot_rom() doesn't take them for Pascal's: they're marked here."""

from commands import *
import apple

load(0xc700, "orig/apple2_io_rpi.orig", "6502", "6da74bb3e82a844aba51e92df9ae8cf6")
apple.apple2()

# The source's names for the routines
for addr, name in ((0xc719, "PageJump"), (0xc71f, "DriverEntry"), (0xc727, "Start"), (0xc753, "Driver"),
                   (0xc765, "GetStatus"), (0xc76d, "ReadBlock"), (0xc790, "read256"), (0xc799, "WriteBlock"),
                   (0xc7bc, "write256"), (0xc7c5, "SendByte"), (0xc7dd, "GetByte")):
    label(addr, name)

# The offsets of its routines for Pascal's communications
for addr, target, name in ((0xc70d, 0xc711, "CommInit"), (0xc70e, 0xc743, "CommRead"),
                           (0xc70f, 0xc749, "CommWrite"), (0xc710, 0xc74f, "CommStatus")):
    entry(target, name)
    byte(addr)
    expr(addr, make_lo(name))
    comment(addr, "Offset of " + name, align=Align.INLINE)

apple.slot_rom(7)
go()
