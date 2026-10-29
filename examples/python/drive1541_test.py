"""Code for the 1541 disk drive, made from
asm_to_create_test_binaries/drive1541_test.asm, loaded at &0500 (buffer 2)
and disassembled with commodore.drive1541(): the jobs it writes to the job
queue (a READ with its track and sector, an EXECUTE whose code in buffer 3
is traced, and a BUMP), the buffers (with a loop whose operands, e.g.
'(buffer_0+1) - 1,y', xa needs written differently), the VIAs, the NMI
vector and the DOS ROM's routines."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_test.orig", "6502", "583f9f28a1cbd3fb3e9cacab5ffe3c97")
commodore.drive1541()
entry(0x0500, "drive_code")
go()
