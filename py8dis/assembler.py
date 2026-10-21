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

    # 'output_filename': Some assemblers (e.g. beebasm and acme) can save the
    # resulting binary to a specific filepath if specified.
    output_filename = None

    def __init__(self):
        self.pending_assertions = {}

    # Expressions (see expression.py)

    def binary_operators(self):
        """A dictionary translating generic binary operator names (e.g. 'AND')
        into this assembler's syntax. None means it's not supported. Names not
        in the dictionary are used as they are (e.g. '+')."""
        return {}

    def unary_operators(self):
        """A dictionary translating generic unary operator names (e.g. 'NOT')
        into this assembler's syntax: either a prefix, or a template where
        '%s' is replaced by the operand (e.g. 'NOT(%s)'). None means it's not
        supported. Names not in the dictionary are used as prefixes."""
        return {}

    def expression_in_context(self, expr, text, context):
        """Returns how the expression 'expr' (whose text is 'text') should be
        written in the given context (see expression.py), for assemblers that
        need something different in some contexts."""
        return text

    def set_output_filename(self, filename):
        self.output_filename = filename

    def assert_expr(self, expr, value):
        self.pending_assertions[expr] = value
