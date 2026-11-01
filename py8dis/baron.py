"""
Baron assembler (https://github.com/waitingforvsync/baron), the spiritual
successor to beebasm

Its syntax is mostly beebasm's ('.label', 'equb', '&' hex, the same binary
operators and precedence), so this is beebasm.py's class with Baron's
sections (which replace beebasm's 'org', 'save' and 'copyblock'), its
assertions, the names it won't take, and a few details. (Measured with Baron
v0.6.0: see the project's Baron plan.)
"""

import os
import re

import beebasm
import config
import expression
import memorymanager
import session
import utils

# The keywords Baron takes to be the start of a statement (its mnemonics,
# including the 65C02's and their aliases, and its directives), so that a
# symbol with one of these names is defined as '@name = value' (in any case).
# (From its statement token table, in assemble.c.)
_KEYWORDS = set("""
    adc and asl bcc bcs beq bit bmi bne bpl brk bvc bvs clc cld cli clv cmp cpx cpy dec dex dey eor
    inc inx iny jmp jsr lda ldx ldy lsr nop ora pha php pla plp rol ror rti rts sbc sec sed sei sta
    stx sty tax tay tsx txa txs tya
    bra dea ina phx phy plx ply stz clr trb tsb
    skip skipto align section endsection equb equs equw equd bitzp bitabs incbin include basic endbasic
    if elif else endif for next macro endmacro function print error assert
    za_pool za_auto za_auto1 za_auto2 za_unreachable za_cancall za_canjump za_return za_returnto
    za_discard za_wipe za_indexedby za_entry za_interrupt""".split())

# The names Baron reserves outright (in any case), which can't be labels at
# all
_RESERVED = {"true", "false", "pi"}

class Baron(beebasm.Beebasm):
    """This class encapsulates Baron-specific syntax and features."""

    def __init__(self):
        super().__init__()
        self._move_sections = {}        # (The number of sections for each move, for their names)

    def get_name(self):
        return "baron"

    def unary_precedence(self):
        # Measured with Baron v0.6.0: '<' and '>' (low and high byte) apply to
        # the whole of the rest of the expression, e.g. '<x+&100' is
        # '<(x+&100)', so they bind less tightly than anything else (as in
        # 64tass and xa, and unlike beebasm). NOT is 'NOT(...)', as in beebasm.
        return { '<': 0, '>': 0 }

    def expression_in_context(self, expr, text, level, context):
        if context == expression.ASSERTION:
            # (The assertion is 'ASSERT (expr) = value': it's always in
            # brackets, since '=' binds more tightly than AND, OR and EOR,
            # and a comparison's result is a boolean, which can't be mixed
            # with a number in them)
            return text
        return super().expression_in_context(expr, text, level, context)

    def direct_operand(self, operand):
        # Baron takes an operand starting with a bracket to be indirect, so
        # 'lda (table+1) - 1,y' is an error; a unary plus makes it a value
        return "+" + operand

    def _check_name(self, name):
        name = str(name)
        if name.lower() in _RESERVED:
            utils.die("Baron doesn't accept '{0}' as a label, since it's one of its constants: rename it".format(name))

    def inline_label(self, name):
        self._check_name(name)
        return super().inline_label(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        # (A symbol named like a keyword, e.g. 'next', is defined with an '@'
        # before the name, and used without it)
        self._check_name(name)
        if str(name).lower() in _KEYWORDS:
            name = "@" + str(name)
        return super().explicit_label(name, value, offset, align_column)

    def uses_current_address(self, text):
        # 'P%' (or '*') is the current address; py8dis only writes 'P%'
        return re.search(r"P%", _without_quoted_text(text), re.IGNORECASE) is not None

    def _filename(self):
        """The file name of the output's section: the name given with
        set_output_filename(), or the asm file's name without its extension,
        or 'pydis'."""
        output_filename = session.current().output_filename
        if output_filename:
            return output_filename
        asm_filename = session.current().asm_filename
        if asm_filename:
            return os.path.splitext(os.path.basename(asm_filename))[0]
        return "pydis"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: how to
        assemble it."""
        self._move_sections = {}
        c = self.comment_prefix()
        asm_filename = session.current().asm_filename
        return [
            c + " Assemble with Baron, which writes the program to the file named in its",
            c + " section (" + self._filename() + "), in the folder given with -p:",
            c + "     baron -p . " + (os.path.basename(asm_filename) if asm_filename else "this_file"),
            "",
        ]

    def _cmos(self):
        return (", cmos = " + utils.force_case("TRUE")) if config.get_cmos() else ""

    def _section_start(self, start_addr):
        """The start of the section that holds all the output, at start_addr."""
        # (The attributes' names stay in lower case, since Baron takes
        # 'FILENAME' to be another attribute, which it ignores)
        return '%s pydis, org = %s, filename = "%s"%s' % (utils.force_case("SECTION"), self.hex4(start_addr), self._filename(), self._cmos())

    def prg_header(self, load_addr):
        """A PRG file's two-byte load address, which starts the section."""
        return ["", self.comment_prefix() + " The PRG file's header: the address to load it at", self._section_start(load_addr - 2),
                utils.make_indent(1) + self.word_prefix() + self.hex4(load_addr)]

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code, the section that holds it all, starting
        at the address at which to assemble (unless a PRG file's header has
        started it); a later range pads the section to its address."""
        if first:
            if memorymanager.prg_header_addr() is not None:
                return [""]
            return ["", self._section_start(start_addr), ""]
        # (The address only moves forwards in a section, padding with zeroes,
        # as beebasm's 'save' saves the zeroes in a gap)
        return ["", "%s%s %s" % (utils.make_indent(1), utils.force_case("SKIPTO"), self.hex4(start_addr)), ""]

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: a section inside the main one, with its own
        address, whose bytes land where it's written and whose labels have
        the runtime addresses. (Each section's name is used once.)"""
        count = self._move_sections.get(move_id, 0) + 1
        self._move_sections[move_id] = count
        name = "move_%d" % move_id if count == 1 else "move_%d_%d" % (move_id, count)
        return [utils.make_indent(1) + "%s %s, org = %s%s" % (utils.force_case("SECTION"), name, self.hex4(dest), self._cmos())]

    def pseudopc_end(self, dest, source, length, move_id):
        return [utils.make_indent(1) + utils.force_case("ENDSECTION"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly, then the end of
        the section: Baron's ASSERT stops with 'Assertion failed' if its
        expression is false."""
        result = []
        if config.get_include_assertions():
            spa = sorted(((str(expr), self.assertion_value(value), expr) for expr, value in self.pending_assertions.items()), key=lambda x: x[:2])
            old = None
            for expr_text, value, expr in spa:
                if old != (expr_text, value):
                    result.append(utils.make_indent(1) + "%s (%s) = %s" % (utils.force_case("ASSERT"), expression.render(expr, expression.ASSERTION), value))
                old = (expr_text, value)
        result.append("")
        result.append(utils.force_case("ENDSECTION"))
        return result

    def char_literal(self, n):
        # There are no escapes in a character literal, and a single quote
        # can't be written as one (a double quote, backslash, ';' or ':' can)
        if utils.isprint(n) and n != ord("'"):
            return "'" + chr(n) + "'"
        return None

    def string_chr(self, n):
        # A '"' in a string is written '""'; a backslash, ';' or ':' is an
        # ordinary character
        if n == ord('"'):
            return '""'
        if utils.isprint(n):
            return chr(n)
        return None

    def include_binary_file(self, binary_filepath):
        # Baron finds the file relative to the source file, so the path (from
        # the folder py8dis is run in) is made relative to the asm file's
        # folder, when it's written to a file
        asm_filename = session.current().asm_filename
        if asm_filename:
            binary_filepath = os.path.relpath(binary_filepath, os.path.dirname(os.path.abspath(asm_filename)))
            binary_filepath = binary_filepath.replace(os.sep, "/")
        return utils.make_indent(1) + utils.force_case("INCBIN") + ' "' + binary_filepath + '"'


def _without_quoted_text(text):
    """The text without its strings and character literals, e.g. for 'P%'
    in an expression."""
    return re.sub(r"\"(?:[^\"]|\"\")*\"|'[^']'", "", text)
