apple2_io_rpi.orig (in examples/orig) is the drive firmware of Terence
Boldt's Apple2-IO-RPi, a card that connects an Apple II to a Raspberry Pi,
for slot 7: the card's 256-byte ROM at $C700, which boots from the card and
makes it a ProDOS block device. It's used as a test of apple.slot_rom() (see
python/apple2_io_rpi.py). It's under the MIT licence (LICENSE, in this
folder).

It was built, unchanged, from DriveFirmware.asm in

    https://github.com/tjboldt/Apple2-IO-RPi

at commit d855d703d8c54f3f32ffd2bcd66e6fe8d30282c6 (2026-06-17), with cc65
2.19 (https://github.com/cc65/cc65), as its Apple2/assemble.sh does for
slot 7 of the classic hardware:

    ca65 DriveFirmware.asm -D HW_TYPE=0 -D SLOT=7 -o DriveSlot7.o
    ld65 DriveSlot7.o -o apple2_io_rpi.orig -C ../.cicd/none.cfg

(assemble.sh builds the firmware for each slot, and the card's other
firmware, into one EPROM image; this is the page for slot 7.)

md5sum:
    6da74bb3e82a844aba51e92df9ae8cf6  apple2_io_rpi.orig
