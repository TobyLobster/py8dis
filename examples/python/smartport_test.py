"""A IIe program (made from asm_to_create_test_binaries/smartport_test.asm)
that finds SmartPort in slot 5 and calls it through a JMP of its own, which
apple.smartport_calls() is given: each call's number and parameter list's
address after the JSR are marked, and tracing carries on after them; the
number is named (e.g. 'SP_READBLOCK') and the call commented ('SmartPort:
read a block'); and the parameter lists are labelled (e.g.
'sp_readblock_params') and marked, with their buffers ('data_buffer',
'status_list', 'control_list'). A call SmartPort doesn't define is
commented with its number, and tracing stops after an extended call, which
isn't decoded. The program's calls to slot 3's and slot 6's ROMs are named
('slot_3_entry', commented 'Start the 80-column firmware (as PR#3 does)')."""

from commands import *
import apple

load(0x0803, "orig/smartport_test.orig", "6502", "d79ecffcffa0e5f17f0a85c834886957")
apple.apple2(model="iie")
apple.smartport_calls(0x085b)
entry(0x0803, "start")
go()
