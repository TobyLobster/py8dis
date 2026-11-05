"""An AppleSingle file (made by asm_to_create_test_binaries/apple_files.asm),
loaded with load_apple_file(): its header's ProDOS file information gives
its file type (BIN) and aux type ($0803, its load address), and its data
fork is loaded there. The output starts with the header (with its entries,
the real name and the ProDOS file information), so it assembles to the
whole file. A BIN file isn't traced, since it may be data, so entry()
traces the program."""

from commands import *

start = load_apple_file("orig/apple_applesingle_test.orig", "6502", "594a6317b42f0939885abb31fb9158c0")
assert start == 0x0803
entry(start, "start")
go()
