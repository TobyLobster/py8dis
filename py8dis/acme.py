"""
Acme assembler
"""

import sys

import config
import session
import utils
import assembler
import traceback

class Acme(assembler.Assembler):
    """This class encapsulates acme-specific syntax and features."""

    def __init__(self):
        super().__init__()

    def get_name(self):
        return "acme"

    def cpus_supported(self):
        return ["6502", "65c02"]

    def hex2(self, n):
        """format a two digit hex number"""
        return "${0}".format(utils.plainhex2(n))

    def hex(self, n):
        # Use two digits for addresses in zero page, otherwise four digits.
        if n <= 0xff:
            return self.hex2(n)
        else:
            return "$%s" % utils.plainhex4(n)

    def hex4(self, n):
        """format a four digit hex number"""
        # WARNING: Normally this should output four digits of hex, but...
        # Older versions of acme don't like things like:
        #
        #     L00A4 = $00A4
        #     LDA (L00A4),Y
        #
        # Because the label's value is defined with four hex digits, acme made
        # the assumption that the address is not zero page. To avoid the issue
        # we only use four digits when necessary.
        return self.hex(n)

    def hex4_for_comment(self, n):
        """A four digit hex number, for use in a comment. (Unlike hex4(), this
        always gives four digits, since acme doesn't read it.)"""
        return "$%s" % utils.plainhex4(n)

    def binary_operators(self):
        """Returns a dictionary that translates generic binary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        return { 'OR': '|'  ,
                  '|': '|'  ,
                'AND': '&'  ,
                  '&': '&'  ,
                'EOR': 'XOR',
                'XOR': 'XOR',
                  '^': 'XOR',
                'DIV': 'DIV',
                  '/': 'DIV',
                'MOD': '%'  ,
                  '%': '%'  ,
                 '!=': '!=' ,
        }

    def binary_precedence(self):
        # Measured by assembling test expressions with acme 0.97
        return { '*': 7, 'DIV': 7, 'MOD': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 3,
                 'EOR': 2,
                 'OR': 1,
        }

    def unary_precedence(self):
        # Measured by assembling test expressions with acme 0.97. Note that '<'
        # and '>' (low and high byte) bind less tightly than '+', so '<x + 1'
        # is the low byte of 'x + 1', but more tightly than AND.
        return { 'NOT': 90,
                 '<': 4, '>': 4,
        }

    def unary_operators(self):
        """Returns a dictionary that translates generic unary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        return { 'NOT': '!',
                   '!': '!',
        }

    def inline_label(self, name):
        """Returns the string for defining a label in the first column."""
        return "%s" % name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly."""
        result = []

        if config.get_cmos():
            result.extend([utils.force_case("!cpu 65c02"), ""])
        return result

    def code_start(self, start_addr, end_addr, first):
        """At the start of the code we provide the address at which to
        assemble."""
        return ["", "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)), ""]

    def code_end(self):
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute."""
        # It is surrounded by '!pseudopc <execution-address> { <code> }'
        return [utils.force_case("!pseudopc %s {" % self.hex(dest))]

    def pseudopc_end(self, dest, source, length, move_id):
        return ["}", ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly"""
        result = []

        # Write the output file if specified
        output_filename = session.current().output_filename
        if output_filename:
            result.extend(['%s "%s", %s' % (utils.force_case("!to"), output_filename, utils.force_case("plain"))])

        # At the end of the assembly, we output assertions.
        if config.get_include_assertions():
            spa = sorted((str(expr), self.hex(value) if type(value) == int else '"' + value + '"') for expr, value in self.pending_assertions.items())
            old = ("", 0)
            for expr, value in spa:
                if old != (expr, value):
                    result.append("%s (%s) != %s {" % (utils.force_case("!if"), expr, value))
                    result.append('%s%s "Assertion failed: %s == %s"' % (utils.make_indent(1), utils.force_case("!error"), expr, value))
                    result.append("}")
                old = (expr, value)

        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda+2 addr'
        return "%s%s+2 %s%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case("!byte ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case("!word ")

    def string_prefix(self):
        # For outputting strings
        return utils.force_case("!text ")

    def char_literal(self, n):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        quote = "'"
        if n == ord('\\'):
            return quote + "\\\\" + quote
        if n == ord('\''):
            return quote + "\\'" + quote
        if utils.isprint(n):
            return quote + chr(n) + quote
        return None

    def string_chr(self, n):
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible
        if n == ord('\\'):
            return "\\\\"
        if n == ord('"'):
            return None
        if utils.isprint(n):
            return chr(n)
        return None

    def binary_format(self, s):
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data
        return s.replace("0", ".").replace("1", "#")

    def sanitise_line(self, s):
        return s

    def supports_signed_integers(self):
        return True

    def include_binary_file(self, binary_filepath):
        return utils.make_indent(1) + utils.force_case("!binary") + ' "' + binary_filepath + '"'
