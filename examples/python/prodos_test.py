"""A ProDOS 8 SYS program (made from asm_to_create_test_binaries/prodos_test.asm,
and copied by the go script to 'prodos_test#ff2000', so load_apple_file()
loads it at $2000 and traces it), with apple.apple2(): each MLI call's
number and parameter list's address are marked, and tracing carries on
after them; the number is named (e.g. 'MLI_OPEN') and the call commented
('ProDOS: open a file'); and the parameter lists are labelled (e.g.
'open_params') and marked, with their pathnames ('pathname', a
length-prefixed string), buffers ('data_buffer', 'io_buffer') and
interrupt handler ('interrupt_handler', traced). The global page's MACHID
and DATE are named."""

from commands import *
import apple

load_apple_file("orig/prodos_test#ff2000", "6502", "3bac7aa9f3fdd66c139c6fa9808daafc")
apple.apple2()
go()
