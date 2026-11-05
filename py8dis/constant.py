"""
Constant

A named constant, given with the constant() command (see docs/commands.md),
e.g. 'num_lives = 3'. disassembly.add_constant() keeps them in the session's
disassembly.constants. disassembly.emit_constants() writes their
definitions near the top of the output, and they're used in expressions
given with expr() (see classification.py, which also checks them). Unlike a
label, a constant isn't put into any instruction by itself.
"""

from align import Align
from format import Format


class Constant:
    """A class representing a constant with its value, name, comment and alignment.

        value: The value of the constant: a number, or a string (written
            in double quotes, for Format.STRING, which is the default for
            a string, or in single quotes, for Format.CHAR)
        name: The name identifier of the constant
        comment: Optional comment describing the constant
        align: The alignment of the comment (defaults to INLINE): INLINE
            puts it at the end of the definition's line, BEFORE_LABEL or
            BEFORE_LINE on the line before it, and AFTER_LABEL or
            AFTER_LINE on the line after it
        format: How the value is written (a Format, see format.py).
            Format.DEFAULT is decimal, or hex with
            config.set_constants_are_decimal(False), for a number (see
            disassembly.constant_value_to_string())
    """
    def __init__(self, value, name, comment = None, align = Align.INLINE, format = Format.DEFAULT):
        self.value = value
        self.name = name
        self.comment = comment
        if comment:
            assert align != None
        self.align = align
        self.format = format

    def __str__(self):
        return "{0}={1} ; {2} [{3}, {4}]".format(self.name, self.value, self.comment, self.align, self.format)

    def __repr__(self):
        return self.__str__()
