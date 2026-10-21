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

    def instruction_operand(self, operand):
        """Returns the operand of an instruction as it should be output. Some
        assemblers (e.g. z88dk) need some operands adjusting."""
        return operand

    def set_output_filename(self, filename):
        self.output_filename = filename

    def assert_expr(self, expr, value):
        self.pending_assertions[expr] = value
