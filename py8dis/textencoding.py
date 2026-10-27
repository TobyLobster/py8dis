"""
Text encodings: how bytes in strings (and in the hex dump's character
column, and in character comments) are shown as text.

- "ascii" (the default): bytes 32-126 are their ASCII characters.
- "petscii": the Commodore machines' character codes (e.g. for CHROUT).
- "screen": Commodore screen codes (as stored in screen memory).

The session's encoding is set with config.set_text_encoding() (e.g. by a
Commodore module), and a string command can be given another, e.g.
string(addr, 5, encoding="screen").

For PETSCII and screen codes, a byte's character is the one ACME's !pet or
!scr turns into that byte, so the text matches ACME's syntax: lower case
letters are the unshifted letters (PETSCII $41-$5A, screen codes $01-$1A) and
upper case ones the shifted letters (PETSCII $C1-$DA, screen codes $41-$5A),
as the text appears in the C64's lower/upper case character set. (In its
default upper case/graphics character set, both show as upper case letters
or graphics.) Bytes whose ACME character would be misleading (e.g. PETSCII
$5C, which is a pound sign on the C64 but backslash in ACME) aren't shown as
text, so they're written as numbers.
"""

import utils


class Encoding:
    """A text encoding: 'chars' maps each byte shown as text to its
    character."""

    def __init__(self, name, chars):
        self.name = name
        self.chars = chars

    def char(self, byte):
        """The character for the byte, or None if it isn't shown as text."""
        return self.chars.get(byte)

    def is_printable(self, byte):
        return byte in self.chars

    def __repr__(self):
        return "Encoding(%r)" % self.name


def _ascii():
    return {c: chr(c) for c in range(32, 127)}

def _petscii():
    # Space, digits and punctuation ($20-$40), [ and ], and the letters
    chars = {c: chr(c) for c in range(0x20, 0x41)}
    chars[0x5b] = "["
    chars[0x5d] = "]"
    for i in range(26):
        chars[0x41 + i] = chr(ord("a") + i)
        chars[0xc1 + i] = chr(ord("A") + i)
    return chars

def _screen():
    # @, the letters, [ and ], and space, digits and punctuation ($20-$3f)
    chars = {0x00: "@", 0x1b: "[", 0x1d: "]"}
    chars.update({c: chr(c) for c in range(0x20, 0x40)})
    for i in range(26):
        chars[0x01 + i] = chr(ord("a") + i)
        chars[0x41 + i] = chr(ord("A") + i)
    return chars

ASCII   = Encoding("ascii", _ascii())
PETSCII = Encoding("petscii", _petscii())
SCREEN  = Encoding("screen", _screen())

ENCODINGS = {e.name: e for e in (ASCII, PETSCII, SCREEN)}

def get(name):
    """The encoding with the given name (stopping with an error if there's
    no such encoding)."""
    if name not in ENCODINGS:
        utils.die("unknown text encoding {0!r} (it must be one of: {1})".format(name, ", ".join(repr(n) for n in ENCODINGS)))
    return ENCODINGS[name]

def current():
    """The session's text encoding (see config.set_text_encoding())."""
    import config
    return get(config.get_text_encoding())
