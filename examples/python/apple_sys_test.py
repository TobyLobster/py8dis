"""A ProDOS SYS file whose name gives its file type and aux type
('apple_sys_test#ff2000', a copy of orig/apple_sys_test.orig that the go
script in asm_to_create_test_binaries makes), loaded with
load_apple_file(): a SYS file is loaded at $2000, and traced from there,
where ProDOS runs it."""

from commands import *

start = load_apple_file("orig/apple_sys_test#ff2000", "6502", "01e4ff32fe03be1de1dca8235f8a8634")
assert start == 0x2000
go()
