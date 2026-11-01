"""
Format

The Format enum: how a constant's value is written where it's defined, e.g.
'sprite_count = 12' or 'sprite_count = $0c'. A control file gives it as
constant(value, name, format=Format.HEX), see commands.constant(), and
disassembly.constant_value_to_string() writes the value.
"""

from enum import auto, Enum

class Format(Enum):
    """How a constant's value is written:

        DEFAULT         decimal or hex, as config.set_constants_are_decimal()
                        says (or for a string value, as STRING)
        HEX             hex, in the assembler's syntax (e.g. $0c or &0c)
        DECIMAL         decimal
        DECIMAL_SIGNED  a byte as a signed number, e.g. -1 for 255
        BINARY          binary, e.g. %00001100 (16 digits for a value that
                        isn't a byte)
        PICTURE_BINARY  binary as a picture, e.g. %....##.. (for graphics)
        CHAR            a character (the value is a one character string),
                        in single quotes, e.g. 'A'
        STRING          a string (the value is a string), in double quotes
    """
    DEFAULT = auto()
    HEX = auto()
    DECIMAL = auto()
    DECIMAL_SIGNED = auto()
    BINARY = auto()
    PICTURE_BINARY = auto()
    CHAR = auto()
    STRING = auto()
