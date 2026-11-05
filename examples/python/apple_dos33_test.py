"""A DOS 3.3 binary file with its 4-byte header (made by
asm_to_create_test_binaries/apple_files.asm), loaded with
load_dos33_binary(): the data is loaded at the load address in the header.
The output starts with the header, so it assembles to the whole file. The
data isn't traced, since it may not be code, so entry() traces the
program."""

from commands import *

start = load_dos33_binary("orig/apple_dos33_test.orig", "6502", "be8da81a2a59bab83ed4605d2aac9e0f")
assert start == 0x6000
entry(start, "start")
go()
