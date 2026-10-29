"""A C64 program with code for the 1541 disk drive in it (made from
asm_to_create_test_binaries/fastload_test.asm), disassembled with
commodore.c64() and commodore.drive1541_code(): the drive code at &083b
runs at &0500 in the drive, so it's moved there, and its addresses get the
1541's names (job_queue, via2_disk_control...), while the C64 code's get the
C64's ($01 is the 6510's port, $d020 the border colour). Its jobs are
commented, and the EXECUTE job's code at &0600 is traced."""

from commands import *
import commodore

load_prg("orig/fastload_test.orig", "6510", "e943c9c532bea6bc50170d6fb9a40d93")
commodore.c64()
drive_move = commodore.drive1541_code(0x0500, 0x083b, 0x0111)
label(0x0500, "drive_code", drive_move)
go()
