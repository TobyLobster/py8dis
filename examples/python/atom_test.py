"""An Acorn Atom program (see asm_to_create_test_binaries/atom_test.asm),
disassembled with acorn.atom(): its OS calls are named and commented, what
it writes with OSWRCH, OSASCI and OSCRLF is commented ('Clear the screen',
'Print "HI"', 'Start a new line'), the string after its call to #F7D1 and
its print loop are found, the kernel routines it calls are named, the
handler it sets the write character vector to is traced and named, and the
hardware and workspace it uses are named."""

from commands import *
import acorn

load(0x2900, "orig/atom_test.orig", "6502", "ca8495d3f556bb95987f2c6dd627974a")
acorn.atom()
entry(0x2900, "start")
go()
