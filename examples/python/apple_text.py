"""Text in the Apple II's high ASCII (ASCII with bit 7 set, the "apple"
text encoding), made from asm_to_create_test_binaries/apple_text.asm:

- a string ending with a CR and a zero (stringz()), with double quotes and
  a backslash in it;
- one whose last character has bit 7 clear (stringhi(), which in high
  ASCII ends at a byte with bit 7 clear), with that character included;
- one ending with a CR, given an expression (a constant) for it;
- an ASCII string (encoding="ascii");
- one that py8dis finds by itself (with go()'s autostring);
- characters printed with COUT (char()), and the character comments on the
  immediate values.

acme writes high ASCII strings as ASCII in an '!xor $80' block, 64tass with
an encoding of its own, ca65 with a character map, and beebasm, Baron and xa
as bytes with the text in a comment."""

from commands import *

load(0x0800, "orig/apple_text.orig", "6502", "a0a112209c68559853aaaf5d4444b599")
config.set_text_encoding("apple")
entry(0x0800, "start")
label(0xfded, "cout")

label(0x0835, "message")
stringz(0x0835)
label(0x084d, "dci_message")
stringhi(0x084d, include_terminator_fn=lambda c: True)
label(0x0851, "line")
string(0x0851, 5)
constant(0x8d, "cr")
expr(0x0855, "cr")
label(0x0856, "ascii_message")
stringz(0x0856, encoding="ascii")
label(0x0860, "found_by_itself")

char(0x080e)
char(0x0813)
expr(0x0818, "cr")
go()
