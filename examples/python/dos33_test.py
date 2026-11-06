"""A DOS 3.3 binary file (made from asm_to_create_test_binaries/dos33_test.asm),
loaded with load_dos33_binary(), with apple.apple2(): DOS's entry points in
page 3 are named and their calls commented. The IOBs whose addresses are
loaded into Y and A for RWTS are labelled ('rwts_iob', 'rwts_iob_2', and
DOS's own, 'IOB') and marked, with names for the fields the code uses
(e.g. 'rwts_iob_track'), the device characteristics table ('rwts_dct', or
DOS's 'DCT') and the sector buffers. The file manager's calls are
commented with what X says, DOS's memory is named (IBSLOT, IBSTAT, the
length and address of the file loaded etc.), and tracing stops after the
JSR to DOS's cold start."""

from commands import *
import apple

start = load_dos33_binary("orig/dos33_test.orig", "6502", "908931e49e9257a01332fe68a1b73dff")
entry(start, "start")
apple.apple2()
go()
