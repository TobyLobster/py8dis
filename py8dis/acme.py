"""
Acme assembler

Writes the output for acme (https://sourceforge.net/projects/acme-crossass/),
for the 6502, the 65C02 and the 6510 (the 6502 with its undocumented
opcodes).

Its syntax: a label is defined by its name alone, '$' starts a hex number,
'!byte', '!word' and '!text' are the data directives, and the operators are
mostly C's ('&', '|', '%', '!' for NOT), with XOR and DIV as words. '<' and
'>' (low and high byte) bind less tightly than '+'.

What py8dis writes for it:

- The output starts with '!cpu 65c02' for the 65C02, or '!cpu 6510' for the
  6510, whose undocumented opcodes acme assembles (but for an instruction
  with several opcodes, only the one acme uses: the others are written as
  data bytes, see undocumented_6502_opcodes()).

- A moved block (see move()) is in a '!pseudopc' block. An absolute
  instruction with an operand in zero page has '+2' after its mnemonic
  (e.g. 'lda+2 l0070'), which forces absolute addressing.

- The assertions at the end are '!if' ... '!error' blocks. A file name
  given with set_output_filename() is in a '!to' line.

- A hex number has only two digits for a value up to $ff, even where four
  would be usual (see hex4()).

- Strings in PETSCII or Commodore screen codes use '!pet' and '!scr'. If
  the session's text encoding is one of these, and the output has character
  literals, it starts with a conversion table ('!ct pet' or '!ct scr'), so
  that a character literal is in that encoding (see conversion_table()).
"""


import config
import session
import utils
import assembler
import textencoding
import cpu6510

class Acme(assembler.Assembler):
    """This class encapsulates acme-specific syntax and features. (See
    assembler.Assembler for what each method is for.)"""

    def __init__(self):
        super().__init__()

    def get_name(self):
        """'acme'."""
        return "acme"

    def cpus_supported(self):
        """The 6502, 65C02 and 6510."""
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """A byte in hex, e.g. $1f."""
        return "${0}".format(utils.plainhex2(n))

    def hex(self, n):
        """A hex number, with two digits up to $ff (e.g. $1f), otherwise
        four."""
        # Use two digits for addresses in zero page, otherwise four digits.
        if n <= 0xff:
            return self.hex2(n)
        else:
            return "$%s" % utils.plainhex4(n)

    def hex4(self, n):
        """A hex number with four digits only if it's above $ff, as hex()
        (see below)."""
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
        """'|', '&' and '%', with XOR and DIV as words."""
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
        """acme's precedence: the shifts bind less tightly than '+', and
        AND, EOR and OR less tightly than them, each at its own level."""
        # Measured by assembling test expressions with acme 0.97
        return { '*': 7, 'DIV': 7, 'MOD': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 3,
                 'EOR': 2,
                 'OR': 1,
        }

    def unary_precedence(self):
        """NOT binds tightly; '<' and '>' between the shifts and AND."""
        # Measured by assembling test expressions with acme 0.97. Note that '<'
        # and '>' (low and high byte) bind less tightly than '+', so '<x + 1'
        # is the low byte of 'x + 1', but more tightly than AND.
        return { 'NOT': 90,
                 '<': 4, '>': 4,
        }

    def unary_operators(self):
        """NOT is '!'."""
        # 'generic name: assembler specific name'
        return { 'NOT': '!',
                   '!': '!',
        }

    def inline_label(self, name):
        """Returns the string for defining a label in the first column: the
        name alone."""
        return "%s" % name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """';'."""
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
        # (Only if some data's formatter is char(): see mainformatter.py)
        if not any(formatter is mainformatter.char_formatter for formatter in session.current().disassembly.format_hint.values()):
            return None
        return {"petscii": "pet", "screen": "scr"}[name]

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: '!cpu
        65c02' for the 65C02, or '!cpu 6510' for the 6510's undocumented
        opcodes, then '!ct' if there's a conversion table (see
        conversion_table())."""
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

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: '* = $2000'."""
        return ["", "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)), ""]

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: '!pseudopc' with the runtime address."""
        # It is surrounded by '!pseudopc <execution-address> { <code> }'
        return [utils.force_case("!pseudopc %s {" % self.hex(dest))]

    def pseudopc_end(self, dest, source, length, move_id):
        """'}', ending the '!pseudopc' block."""
        return ["}", ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly: '!to' with the
        file name from set_output_filename(), if any, then the assertions,
        each as '!if (expr) != value { !error ... }'."""
        result = []

        # Write the output file if specified
        output_filename = session.current().output_filename
        if output_filename:
            result.extend(['%s "%s", %s' % (utils.force_case("!to"), output_filename, utils.force_case("plain"))])

        # At the end of the assembly, we output assertions.
        if config.get_include_assertions():
            spa = sorted((str(expr), self.assertion_value(value)) for expr, value in self.pending_assertions.items())
            old = ("", 0)
            for expr, value in spa:
                if old != (expr, value):
                    result.append("%s (%s) != %s {" % (utils.force_case("!if"), expr, value))
                    result.append('%s%s "Assertion failed: %s == %s"' % (utils.make_indent(1), utils.force_case("!error"), expr, value))
                    result.append("}")
                old = (expr, value)

        return result

    def undocumented_6502_opcodes(self):
        """cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES."""
        # With '!cpu 6510' acme assembles all the undocumented mnemonics, but
        # where an instruction has several opcodes (e.g. ANC is &0b and &2b;
        # JAM and the NOPs have many) it uses only one, so the others are
        # written as data. (Found by assembling each with acme 0.97 of 31 Jan 2021.)
        return cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES

    def undocumented_6502_mnemonic(self, mnemonic):
        """'ASR' for ALR; otherwise py8dis's name."""
        # acme 0.97 of 31 Jan 2021 accepts ALR (&4b) as well as ASR, but
        # 0.97 of 4 Jul 2020 (and older versions) only ASR
        return "ASR" if mnemonic == "ALR" else mnemonic

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        """The mnemonic with '+2' after it, e.g. 'lda+2 addr'."""
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda+2 addr'
        return "%s%s+2 %s%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def force_zp_label_prefix(self):
        """'<' (the low byte)."""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def byte_prefix(self):
        """'!byte '."""
        # For outputting bytes
        return utils.force_case("!byte ")

    def word_prefix(self):
        """'!word '."""
        # For outputting words
        return utils.force_case("!word ")

    def string_prefix(self):
        """'!text ', or '!raw ' if there's a conversion table."""
        # For outputting strings (in ASCII: !raw if there's a conversion
        # table, which would convert !text)
        if self.conversion_table() is not None:
            return utils.force_case("!raw ")
        return utils.force_case("!text ")

    def char_literal(self, n):
        """A printable character in single quotes, with a backslash before a
        backslash or a single quote; None if there's a conversion table."""
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
        """A printable character as it is, with a backslash doubled, except a
        double quote."""
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
        """With a conversion table, a character literal in the session's
        encoding (with a backslash before a backslash or single quote);
        otherwise only in ASCII, as the base class."""
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
        """'!pet ' for PETSCII and '!scr ' for screen codes; otherwise as the
        base class (string_prefix() for ASCII)."""
        # acme's !pet and !scr convert the text to PETSCII or screen codes
        # (see textencoding.py, whose characters for these are acme's)
        if encoding.name == "petscii":
            return utils.force_case("!pet ")
        if encoding.name == "screen":
            return utils.force_case("!scr ")
        return super().text_directive(encoding)

    def text_chr(self, n, encoding):
        """The encoding's character for the byte, with a backslash doubled
        (None for a double quote, or a byte the encoding has no character
        for)."""
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        if c is None or c == '"':
            return None
        if c == "\\":
            return "\\\\"
        return c

    def binary_format(self, s):
        """'%' then the digits, e.g. %00101100."""
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        """'.' for each 0 and '#' for each 1, e.g. %..#.##.."""
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data
        return s.replace("0", ".").replace("1", "#")

    def sanitise_line(self, s):
        """The line as it is."""
        return s

    def supports_signed_integers(self):
        """True."""
        return True

    def include_binary_file(self, binary_filepath):
        """'!binary "file"'."""
        return utils.make_indent(1) + utils.force_case("!binary") + ' "' + binary_filepath + '"'
