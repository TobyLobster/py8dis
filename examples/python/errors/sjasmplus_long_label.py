"""A label name longer than sjasmplus allows (64 characters)."""

import sys
sys.argv[1:] = ["--sjasmplus"]

from commands import *

load(0x0000, "orig/trace_z80.orig", "z80")
label(0x0000, "a_label_name_that_is_much_too_long_for_sjasmplus_which_allows_64_chars")
entry(0x0000)
go()
