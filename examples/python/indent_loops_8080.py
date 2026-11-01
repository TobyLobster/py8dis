"""8080 code with config.set_indent_loops(True), which indents the code of
each loop. The binary is a copy of example8080's (see
asm_to_create_test_binaries/go), whose copy loop is indented. This used to
stop py8dis with an error of its own (a Python exception), since the 8080's
instructions couldn't be indented."""

from commands import *

config.set_indent_loops(True)

load(0x1000, "orig/indent_loops_8080.orig", "8080", "9dba35b10999191dcd44aab0a5e32e14")
entry(0x1000)

go()
