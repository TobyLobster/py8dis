"""Four cards' ROMs (made from asm_to_create_test_binaries/slot_roms_test.asm,
loaded at $C200-$C5FF), with apple.slot_rom() for each slot. Each ROM's
entry at $Cn00 is traced and named (e.g. 'slot_2_entry'), and its slot's
I/O named (e.g. 'slot_2_io+8'), with the accesses indexed by the slot times
16 named as the card's ('card_io_9'), not the Disk II's:
- slot 2, a Pascal 1.1 serial card: BASIC's entry points at $C205 and
  $C207, its device signature, and its INIT, READ, WRITE and STATUS
  routines, from their offsets;
- slot 3, a card with no ID bytes;
- slot 4, a mouse card: its Pascal routines and the mouse's (SETMOUSE
  etc.);
- slot 5, a SmartPort device: its ID bytes, number of blocks, status byte
  and ProDOS driver, with ProDOS's parameters in zero page named
  ('driver_command' etc.), and its SmartPort dispatcher, whose call in the
  boot code is decoded, with its parameter list; the boot code sets MSLOT."""

from commands import *
import apple

load(0xc200, "orig/slot_roms_test.orig", "6502", "c8cd3c47d81c0a8c6ea176e277eb3de2")
apple.apple2()
for slot in (2, 3, 4, 5):
    apple.slot_rom(slot)
go()
