"""An Applesoft program with machine code after it (made from
asm_to_create_test_binaries/applesoft_test.asm), with apple.apple2() and
apple.applesoft_program(): its lines are listed in comments (e.g. '; 10
HOME : PRINT "HELLO, WORLD"'), and the machine code that line 30 CALLs is
traced (call_entry); CALL -936 is the Monitor's HOME, which isn't loaded.
The machine code's calls to Applesoft's routines are commented (e.g. STROUT,
whose string is marked, 'Print 4660' for LINPRT, and the hi-res routines'
coordinates), its zero page is named, and the handlers that the USR and &
vectors are set to are traced and named."""

from commands import *
import apple

load(0x0801, "orig/applesoft_test.orig", "6502", "cde315b480d00576a1e57cd653ddf6ea")
apple.apple2()
apple.applesoft_program()
go()
