"""
Assembler base class
"""

import utils

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

    def wrapped_branch_operand(self, label, offset):
        """The operand of a relative branch whose target wraps round the top
        or bottom of memory (e.g. a branch back from &0002 to &fff2), given
        the label at the target and the offset from the branch to the
        target as if it didn't wrap (e.g. -16). acme and xa wrap the target
        like the 6502, so the label will do."""
        return label

    def can_force_absolute(self):
        """Can the assembler be told to use absolute addressing for an
        instruction whose operand is a zero page address? (See
        force_abs_instruction().)"""
        return True

    def force_abs_instruction(self, mnemonic, prefix, operand, suffix):
        """The text of an instruction (indented) using absolute addressing,
        although its operand is a zero page address. The mnemonic and the
        operand's prefix and suffix are given, and the operand's text. (Only
        used if can_force_absolute().)"""
        raise NotImplementedError

    def direct_operand(self, operand):
        """The text of an operand that isn't indirect (e.g. for 'lda
        operand,y') but starts with a bracket, e.g. '(table+1) - 1', which
        some assemblers would take to be indirect."""
        return operand

    def encoded_char_literal(self, n, encoding):
        """A character literal for the byte n in the given text encoding (a
        textencoding.Encoding), e.g. "'a'", or None if there isn't one. Only
        ASCII by default (see char_literal())."""
        return self.char_literal(n) if encoding.name == "ascii" else None

    def text_directive(self, encoding):
        """The directive for a string in the given encoding (a
        textencoding.Encoding), e.g. '.asc ', or None if the assembler has
        none for it, in which case the string is written as bytes, with its
        text in a comment."""
        return self.string_prefix() if encoding.name == "ascii" else None

    def text_encoding_lines(self, encoding):
        """(lines before, lines after) a string in the given encoding (one
        with a text_directive()), e.g. to select the encoding for it."""
        return [], []

    def text_chr(self, n, encoding):
        """How the byte n is written inside the quotes of a string in the
        given encoding (one with a text_directive()), or None if it's
        written as a number."""
        return self.string_chr(n) if encoding.name == "ascii" else None

    def undocumented_6502_opcodes(self):
        """The 6502's undocumented opcodes (see cpu6510.py) that the
        assembler can assemble from their mnemonics. Others are written as
        data bytes."""
        return frozenset()

    def undocumented_6502_mnemonic(self, mnemonic):
        """The assembler's mnemonic for one of the undocumented opcodes it
        accepts (see undocumented_6502_opcodes()), given py8dis's name for it
        (in upper case)."""
        return mnemonic

    def prg_header(self, load_addr):
        """The lines at the start of the output for a PRG file loaded with
        load_prg(): its two-byte load address, assembled just before the
        data, so that the output assembles to the whole PRG file. (The
        code_start() that follows sets the address to load_addr.) None if the
        assembler can't do this."""
        org = [line for line in self.code_start(load_addr - 2, load_addr, True) if line.strip()]
        return ["", self.comment_prefix() + " The PRG file's header: the address to load it at"] + org + [utils.make_indent(1) + self.word_prefix() + self.hex4(load_addr)]

    def hex4_for_comment(self, n):
        """A four digit hex number, for use in a comment (e.g. the memory
        region headings), where it's only read, not assembled."""
        return self.hex4(n)

    def assert_expr(self, expr, value):
        self.pending_assertions[expr] = value
