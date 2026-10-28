"""PETSCII and screen code text: config.set_text_encoding("petscii") makes
PETSCII the session's text encoding (for strings, the hex dump and character
comments), and the string commands' encoding option gives a string another
one. acme writes them with !pet and !scr; beebasm and xa as bytes, with the
text in a comment. A character literal is in the session's encoding too. (Made from asm_to_create_test_binaries/petscii_test.asm.)"""

from commands import *

config.set_text_encoding("petscii")

load(0xc000, "orig/petscii_test.orig", "6502", "450427b438e2e0859623137a4d24c7e8")
label(0xffd2, "chrout")
entry(0xc000, "start")

stringz(0xc023)                                         # message
stringz(0xc03c)                                         # symbols (some bytes aren't text)
string(0xc04e, 21, encoding="screen")                   # title
stringz(0xc063, encoding="ascii")                       # ascii_text
stringhi(0xc06e, include_terminator_fn=lambda c: True)  # hi_string
# (found, at &c072, is left for autostring())
stringhi(0xc086, include_terminator_fn=lambda c: True, encoding="ascii")  # ascii_hi_string

# The character CHROUT outputs, as a character literal: acme then has
# '!ct pet', so that 'a' is PETSCII (and the ASCII string is '!raw', since
# '!text' would be converted, and the ASCII string's terminator is '$80 + $6b'
# rather than "$80 + 'k'"); beebasm and xa have no PETSCII character
# literals, so it's a number, with the character in a comment
char(0xc01e)

go()
