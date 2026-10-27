"""PETSCII and screen code text: config.set_text_encoding("petscii") makes
PETSCII the session's text encoding (for strings, the hex dump and character
comments), and the string commands' encoding option gives a string another
one. acme writes them with !pet and !scr; beebasm and xa as bytes, with the
text in a comment. (Made from asm_to_create_test_binaries/petscii_test.asm.)"""

from commands import *

config.set_text_encoding("petscii")

load(0xc000, "orig/petscii_test.orig", "6502", "d03b990c44e02b84695870a80d9bb92d")
label(0xffd2, "chrout")
entry(0xc000, "start")

stringz(0xc023)                                         # message
stringz(0xc03c)                                         # symbols (some bytes aren't text)
string(0xc04e, 21, encoding="screen")                   # title
stringz(0xc063, encoding="ascii")                       # ascii_text
stringhi(0xc06e, include_terminator_fn=lambda c: True)  # hi_string
# (found, at &c072, is left for autostring())

go()
