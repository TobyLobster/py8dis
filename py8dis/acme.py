"""
Acme assembler
"""

import sys

import config
import session
import utils
import assembler
import textencoding
import traceback

class Acme(assembler.Assembler):
    """This class encapsulates acme-specific syntax and features."""

    def __init__(self):
        super().__init__()

    def get_name(self):
        return "acme"

    def cpus_supported(self):
        return ["6502", "65c02", "6510"]

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

    def conversion_table(self):
        """acme's conversion table for character literals and !text, if the
        output needs one: 'pet' or 'scr' if the session's text encoding is
        PETSCII or screen codes, and there are character literals in it
        (from char(), e.g. by commodore.py's CHROUT hook), otherwise None.
        With one, a character literal like 'a' is that encoding's byte, so
        an ASCII string is written with !raw, rather than !text, which would
        be converted, and an ASCII character literal can't be written."""
        import mainformatter
        import textencoding
        name = textencoding.current().name
        if name == "ascii":
            return None
        if not any(formatter is mainformatter.char_formatter for formatter in session.current().disassembly.format_hint.values()):
            return None
        return {"petscii": "pet", "screen": "scr"}[name]

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly."""
        result = []

        if config.get_cmos():
            result.extend([utils.force_case("!cpu 65c02"), ""])
        elif getattr(session.current().cpu, "has_undocumented_opcodes", False):
            result.extend([utils.force_case("!cpu 6510"), ""])
        table = self.conversion_table()
        if table is not None:
            result.extend([utils.force_case("!ct " + table) + " " + self.comment_prefix() + " (so a character literal, e.g. 'a', is " +
                           ("PETSCII" if table == "pet" else "a screen code") + ")", ""])
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

    def undocumented_6502_opcodes(self):
        # With '!cpu 6510' acme assembles all the undocumented mnemonics, but
        # where an instruction has several opcodes (e.g. ANC is &0b and &2b;
        # JAM and the NOPs have many) it uses only one, so the others are
        # written as data. (Found by assembling each with acme 0.97 of 31 Jan 2021.)
        return self._UNDOCUMENTED_6502_OPCODES

    def undocumented_6502_mnemonic(self, mnemonic):
        # acme 0.97 of 31 Jan 2021 accepts ALR (&4b) as well as ASR, but
        # 0.97 of 4 Jul 2020 (and older versions) only ASR
        return "ASR" if mnemonic == "ALR" else mnemonic

    _UNDOCUMENTED_6502_OPCODES = frozenset([
        0x02, 0x03, 0x04, 0x07, 0x0b, 0x0c, 0x0f, 0x13, 0x14, 0x17, 0x1b, 0x1c, 0x1f, 0x23,
        0x27, 0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f,
        0x63, 0x67, 0x6b, 0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x80, 0x83, 0x87, 0x8b, 0x8f, 0x93,
        0x97, 0x9b, 0x9c, 0x9e, 0x9f, 0xa3, 0xa7, 0xab, 0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3,
        0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xef, 0xf3, 0xf7, 0xfb, 0xff,
    ])

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
        # For outputting strings (in ASCII: !raw if there's a conversion
        # table, which would convert !text)
        if self.conversion_table() is not None:
            return utils.force_case("!raw ")
        return utils.force_case("!text ")

    def char_literal(self, n):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        if self.conversion_table() is not None:
            # (It would be converted)
            return None
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

    def encoded_char_literal(self, n, encoding):
        # In the session's encoding, with its conversion table (see
        # conversion_table())
        if encoding.name == "ascii" or encoding.name != textencoding.current().name or self.conversion_table() is None:
            return super().encoded_char_literal(n, encoding)
        c = encoding.char(n)
        if c is None:
            return None
        if c in ("\\", "'"):
            return "'\\" + c + "'"
        return "'" + c + "'"

    def text_directive(self, encoding):
        # acme's !pet and !scr convert the text to PETSCII or screen codes
        # (see textencoding.py, whose characters for these are acme's)
        if encoding.name == "petscii":
            return utils.force_case("!pet ")
        if encoding.name == "screen":
            return utils.force_case("!scr ")
        return super().text_directive(encoding)

    def text_chr(self, n, encoding):
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        if c is None or c == '"':
            return None
        if c == "\\":
            return "\\\\"
        return c

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
