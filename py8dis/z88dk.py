"""
z88dk assembler (z88dk-z80asm), for the 8080 (with -m8080) or the Z80 (with
-mz80)
"""

import sys

import config
import expression
import utils
import assembler

class Z88DK(assembler.Assembler):
    """This class encapsulates z88dk-specific syntax and features."""

    def __init__(self):
        super().__init__()

    def get_name(self):
        return "z88dk"

    def cpus_supported(self):
        return ["8080", "z80"]

    def undocumented_z80_accepted(self, kind):
        # (Checked with z88dk-z80asm v2.4, -mz80. It doesn't accept the
        # duplicates, e.g. 'neg' for ED 4C.)
        return kind in ("index_halves", "sll", "indexed_cb_register", "in_f_c", "out_c_0")

    def hex2(self, n):
        """format a two digit hex number"""
        return "$%s" % utils.plainhex2(n)

    def hex(self, n):
        """format a hex number"""
        if n <= 0xff:
            return self.hex2(n)
        else:
            return "$%s" % utils.plainhex4(n)

    def hex4(self, n):
        """format a four digit hex number"""
        # WARNING: Normally this should output four digits of hex, but...
        # z88dk doesn't like things like:
        #
        #     LDA $00A4,Y
        #
        # z88dk makes the assumption that the address is not zero page.
        # To avoid the issue we only use four digits when necessary.
        return self.hex(n)

    def binary_operators(self):
        """Returns a dictionary that translates generic binary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        # (Checked against z88dk-z80asm: C-style operators, '!=' gives 1 if true)
        return { 'OR': '|',
                  '|': '|',
                'AND': '&',
                  '&': '&',
                'EOR': '^',
                'XOR': '^',
                  '^': '^',
                'DIV': '/',
                  '/': '/',
                'MOD': '%',
                  '%': '%',
                 '!=': '!=',
        }

    def unary_operators(self):
        """Returns a dictionary that translates generic unary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        # Note: in z88dk-z80asm '!' is logical NOT, '~' is bitwise NOT
        return { 'NOT': '~',
                   '!': '~',
        }

    def binary_precedence(self):
        # Measured by assembling test expressions with z88dk-z80asm (v2.4 and
        # the development version of 21 Oct 2026). Note that '|' and '^' bind
        # equally tightly, unlike in C.
        return { '*': 7, 'DIV': 7, 'MOD': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 4,
                 'OR': 3, 'EOR': 3,
        }

    def unary_precedence(self):
        return { 'NOT': 90 }

    def unary_rewrite(self, op, operand, nested):
        # z88dk-z80asm has no '<' and '>' (low and high byte) operators
        if op == '<':
            return expression.Binary(operand, 'AND', expression.Num(0xff, "hex"))
        if op == '>':
            return expression.Binary(operand, '>>', expression.Num(8))
        return None

    def expression_in_context(self, expr, text, level, context):
        if context == expression.OPERAND:
            # z88dk-z80asm treats an operand that is in brackets as an
            # indirect (Z80 style) value, warning 'interpreting indirect value
            # as immediate' before assembling it correctly anyway. So an
            # operand that starts with a bracket gets a unary plus, e.g.
            # 'mvi a, +(x + 1) & $ff', which assembles to the same thing
            # without the warning.
            if text.startswith("("):
                return "+" + text
        return text

    def wrapped_branch_operand(self, label, offset):
        # z88dk-z80asm doesn't wrap a relative jump's target, but takes an
        # address past the top or bottom of memory, so give it relative to
        # the jump
        return "${0:+d}".format(offset)

    def inline_label(self, name):
        """Returns the string for defining a label in the first column."""
        return "{0}:".format(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s%s %s%s" % (utils.tab_to(name + " ", align_column), utils.force_case("EQU"), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly."""
        return []

    def prg_header(self, load_addr):
        # (A second org would start a separate section)
        return None

    def code_start(self, start_addr, end_addr, first):
        """At the start of the code we provide the address at which to
        assemble."""
        return ["", "%s%s %s" % (utils.make_indent(1), utils.force_case("ORG"), self.hex4(start_addr)), ""]

    def code_end(self):
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: z88dk-z80asm's PHASE, which assembles the code
        that follows for the given address."""
        return [utils.make_indent(1) + utils.force_case("PHASE") + " " + self.hex(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        return [utils.make_indent(1) + utils.force_case("DEPHASE"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly"""
        result = []

        if config.get_include_assertions():
            spa = sorted((str(expr), self.hex(value) if type(value) == int else '"' + value + '"') for expr, value in self.pending_assertions.items())
            for expr, value in spa:
                result.append("; ASSERT ((%s) == %s)" % (expr, value))

        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda !addr,x'
        return "%s%s !%s%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return ""

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case("DB ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case("DW ")

    def string_prefix(self):
        # For outputting strings
        return utils.force_case("DB ")

    def string_chr(self, i):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        if i == ord('\\'):
            return '\\\\'
        if i == ord('"'):
            return '\\"'
        if utils.isprint(i):
            return chr(i)
        return None

    def binary_format(self, s):
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        # Converts a string of '0' and '1's into '-' and '#'s for visualising
        # data
        return "%\"" + s.replace("0", "-").replace("1", "#").replace("%", "") + "\""

    def sanitise_line(self, s):
        return s

    def supports_signed_integers(self):
        return True

    def include_binary_file(self, binary_filepath):
        return utils.make_indent(1) + utils.force_case("BINARY") + ' "' + binary_filepath + '"'
