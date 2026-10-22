"""
Assembler base class
"""

class Assembler:
    """The base assembler class. Classes representing particular assemblers such
    as acme, beebasm etc are derived from this class."""

    # 6502 assemblers vary in whether they output 'ROL A' or just 'ROL'. The
    # 'explicit_a' variable indicates whether the 'A' suffix should be output
    # for instructions with an implicit accumulator.
    explicit_a = False

    # At the end of the assembly output, py8dis also outputs a list of
    # assertions about the values of variables. This acts as a check that py8dis
    # is producing valid output in situations where it cannot otherwise easily
    # tell. This helps make sure that the output will byte-for-byte correspond
    # with the original binary.
    #
    # 'pending_assertions' is a dictionary holding the assertions as key-value
    # pairs. (It's created in __init__, so each assembler object has its own.)

    def __init__(self):
        self.pending_assertions = {}

    # Expressions (see expression.py)

    def binary_operators(self):
        """A dictionary translating generic binary operator names (e.g. 'AND')
        into this assembler's syntax. None means it's not supported. Names not
        in the dictionary are used as they are (e.g. '+')."""
        return {}

    def binary_precedence(self):
        """A dictionary giving how tightly each generic binary operator binds
        (a higher number binds more tightly). Operators not in the dictionary
        are always bracketed when used in a larger expression."""
        return {}

    def unary_operators(self):
        """A dictionary translating generic unary operator names (e.g. 'NOT')
        into this assembler's syntax: either a prefix, or a template where
        '%s' is replaced by the operand (e.g. 'NOT(%s)'). None means it's not
        supported. Names not in the dictionary are used as prefixes."""
        return {}

    def unary_precedence(self):
        """A dictionary giving how tightly each generic unary (prefix) operator
        binds, on the same scale as binary_precedence()."""
        return {}

    def unary_rewrite(self, op, operand, nested):
        """For an assembler that writes a generic unary operator another way
        (e.g. the low byte as 'x & $ff'), returns the expression to use
        instead, otherwise None. 'nested' says whether it's part of a larger
        expression."""
        return None

    def expression_in_context(self, expr, text, level, context):
        """Returns how the expression 'expr' (whose text is 'text', and whose
        precedence level is 'level') should be written in the given context
        (see expression.py), for assemblers that need something different in
        some contexts."""
        return text

    def assert_expr(self, expr, value):
        self.pending_assertions[expr] = value
