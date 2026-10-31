"""
64tass assembler
"""

import re

import config
import session
import utils
import assembler
import cpu6510
import textencoding

# The names of the encodings the output defines for PETSCII and screen codes
# (not 64tass's own 'screen', which '64tass -a' changes, as it does 'none',
# which is ASCII without it)
_ENCODING_NAMES = {"ascii": "none", "petscii": "petscii", "screen": "screencodes"}

class Tass64(assembler.Assembler):
    """This class encapsulates 64tass-specific syntax and features. (Tested
    with 64tass 1.59.3120: the output is assembled with '64tass -b', which
    writes a plain binary, without a load address.)"""

    def __init__(self):
        super().__init__()
        # 64tass accepts 'rol' for 'rol a', but not 'inc' for the 65C02's
        # 'inc a', so the A is always given
        self.explicit_a = True

    def get_name(self):
        return "64tass"

    def cpus_supported(self):
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """format a two digit hex number"""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """format a four digit hex number"""
        # (64tass chooses zero page or absolute addressing from an operand's
        # value, not how it's written, so '$0012' is zero page)
        return "${0}".format(utils.plainhex4(n))

    def hex(self, n):
        """format a hex number"""
        if n <= 0xff:
            return self.hex2(n)
        return self.hex4(n)

    def binary_operators(self):
        """Returns a dictionary that translates generic binary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
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

    def binary_precedence(self):
        # Measured by assembling test expressions with 64tass 1.59.3120 (as
        # in C)
        return { '*': 7, 'DIV': 7, 'MOD': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 4,
                 'EOR': 3,
                 'OR': 2,
        }

    def unary_precedence(self):
        # In 64tass '<' and '>' (low and high byte) apply to the whole of the
        # rest of the expression, e.g. '>ab+$100' is '>(ab+$100)' and even
        # '>ab==$12' is '>(ab==$12)', so they bind less tightly than anything
        # else (as in xa). '~' (NOT) binds tightly: '~1+3' is 1.
        return { '<': 0, '>': 0, 'NOT': 90 }

    def unary_operators(self):
        """Returns a dictionary that translates generic unary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        return { 'NOT': '~',
                   '!': '~',
        }

    def _check_name(self, name):
        # 64tass takes a label starting with '_' to be a 'cheap local' label,
        # which can't be used after the next label
        if str(name).startswith("_"):
            utils.die("64tass takes a label starting with '_' to be local to the label before it, so '{0}' can't be used: rename it".format(name))

    def inline_label(self, name):
        """Returns the string for defining a label in the first column."""
        self._check_name(name)
        return name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        self._check_name(name)
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly."""
        # (The CPU's name is a string, which 64tass reads case sensitively, so
        # it's always lower case)
        result = []
        if config.get_cmos():
            result += [utils.force_case(".cpu") + ' "65c02"', ""]
        elif getattr(session.current().cpu, "has_undocumented_opcodes", False):
            result += [utils.force_case(".cpu") + ' "6502i"', ""]
        return result + self._encoding_definitions()

    # Text encodings. 64tass's '.text' and character literals use the current
    # encoding, set with '.enc', which can be defined with '.cdef' (each
    # character, or range of characters, and its byte). The output defines
    # PETSCII and screen codes (as in textencoding.py), if it has text in
    # them, and selects the session's encoding (see _main_encoding()), so a
    # string or character literal in it is written as text. A string in
    # another encoding (e.g. ASCII in a C64 program) selects its own encoding
    # just for that string (see text_encoding_lines()). Character literals
    # are only in the main encoding.

    def _main_encoding(self):
        """The encoding selected for the output as a whole: the session's."""
        return textencoding.current()

    def _encoding_definitions(self):
        """The lines defining and selecting the encodings the output uses
        (nothing if it has no text other than ASCII): each non-ASCII encoding
        a string uses, and the session's, if it isn't ASCII and the output
        has strings or character literals in its encoding."""
        import classification
        import mainformatter
        used = set()
        any_strings = False
        for c in session.current().classifications.classifications:
            if isinstance(c, classification.String):
                any_strings = True
                used.add(c.encoding.name)
        main = self._main_encoding()
        if main.name != "ascii":
            if any_strings or any(formatter is mainformatter.char_formatter for formatter in session.current().disassembly.format_hint.values()):
                used.add(main.name)
        used.discard("ascii")
        if not used:
            return []
        result = [self.comment_prefix() + " Text encodings (for '.text' and character literals)"]
        # (Defining an encoding selects it, so the main one is defined last;
        # if it's ASCII, 64tass's 'none' is selected after the others)
        for name in sorted(used, key=lambda n: (n == main.name, n)):
            result.append(self._enc_line(name))
            result += self._cdef_lines(textencoding.get(name))
        if main.name not in used:
            result.append(self._enc_line(main.name))
        return result + [""]

    def _enc_line(self, encoding_name):
        return '%s%s "%s"' % (utils.make_indent(1), utils.force_case(".enc"), _ENCODING_NAMES[encoding_name])

    def _cdef_lines(self, encoding):
        """'.cdef' lines defining the encoding's characters: each run of
        characters with consecutive codes, whose bytes are consecutive too
        (e.g. '.cdef "az", $41')"""
        pairs = sorted((ord(char), byte) for byte, char in encoding.chars.items())
        runs = []
        for code, byte in pairs:
            if runs and runs[-1][1] == code - 1 and runs[-1][2] == byte - (code - runs[-1][0]):
                runs[-1][1] = code
            else:
                runs.append([code, code, byte])

        def quoted(text):
            # (A string can be in either kind of quote; inside it, its own
            # kind is doubled)
            quote = "'" if '"' in text else '"'
            return quote + text.replace(quote, quote * 2) + quote

        return ["%s%s %s, %s" % (utils.make_indent(1), utils.force_case(".cdef"), quoted(chr(first) + chr(last)), self.hex2(byte))
                for first, last, byte in runs]

    def text_encoding_lines(self, encoding):
        # A string in an encoding other than the main one selects its own
        # encoding, then the main one again
        main = self._main_encoding()
        if encoding.name == main.name:
            return [], []
        return [self._enc_line(encoding.name)], [self._enc_line(main.name)]

    _ENC_LINE = re.compile(r'^\s*\.enc "([^"]*)"\s*$', re.IGNORECASE)

    def tidy_output(self, lines):
        # Strings in other encodings than the main one each select their own,
        # then the main one again (see text_encoding_lines()), so for two in
        # a row there are lines that change nothing: the main encoding
        # selected just before another, or an encoding selected when it
        # already is. Leave those out.
        result = []
        current = None
        for i, line in enumerate(lines):
            m = self._ENC_LINE.match(line)
            if m is not None:
                if i + 1 < len(lines) and self._ENC_LINE.match(lines[i + 1]):
                    continue
                if m.group(1) == current:
                    continue
                current = m.group(1)
            result.append(line)
        return result

    def text_directive(self, encoding):
        return utils.force_case(".text ")

    def text_chr(self, n, encoding):
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        if c == '"':
            return '""'
        return c

    def encoded_char_literal(self, n, encoding):
        # Only in the main encoding (see above)
        if encoding.name != self._main_encoding().name:
            return None
        if encoding.name == "ascii":
            return self.char_literal(n)
        c = encoding.char(n)
        if c is None:
            return None
        return '"\'"' if c == "'" else "'" + c + "'"

    def code_start(self, start_addr, end_addr, first):
        """At the start of the code we provide the address at which to
        assemble."""
        return ["", "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)), ""]

    def code_end(self):
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute."""
        return [utils.force_case(".logical %s" % self.hex(dest))]

    def pseudopc_end(self, dest, source, length, move_id):
        return [utils.force_case(".here"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly"""
        result = []

        # 64tass's '.cerror condition, "message"' stops with the message if
        # the condition is true
        if config.get_include_assertions():
            spa = sorted((str(expr), self.assertion_value(value)) for expr, value in self.pending_assertions.items())
            old = ("", 0)
            for expr, value in spa:
                if old != (expr, value):
                    result.append('%s (%s) != %s, "Assertion failed: %s == %s"' % (utils.force_case(".cerror"), expr, value, expr, value.replace('"', '""')))
                old = (expr, value)

        return result

    def undocumented_6502_opcodes(self):
        # With '.cpu "6502i"' 64tass assembles all the undocumented mnemonics
        # (with py8dis's names), but where an instruction has several opcodes
        # it uses only one, the same as acme (found by assembling each with
        # 64tass 1.59.3120), so the others are written as data.
        return cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda @w addr,x'
        return "%s%s %s%s%s%s" % (utils.make_indent(1), instruction, prefix, utils.force_case("@w "), operand, suffix)

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case(".byte ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case(".word ")

    def string_prefix(self):
        # For outputting strings (64tass's default encoding, 'none', leaves
        # the bytes as they are)
        return utils.force_case(".text ")

    def char_literal(self, n):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible (only if the main encoding
        # is ASCII, see above)
        if self._main_encoding().name != "ascii":
            return None
        if n == ord("'"):
            return '"\'"'
        if utils.isprint(n):
            return "'" + chr(n) + "'"
        return None

    def string_chr(self, n):
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible. (A '"' is written '""';
        # a backslash is an ordinary character.)
        if n == ord('"'):
            return '""'
        if utils.isprint(n):
            return chr(n)
        return None

    def binary_format(self, s):
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data. 64tass doesn't support this ('%..##' is an error).
        return s

    def sanitise_line(self, s):
        return s

    def supports_signed_integers(self):
        # '.byte -1' is an error ('value needs to be non-negative'), so don't
        # use signed integers
        return False

    def include_binary_file(self, binary_filepath):
        return utils.make_indent(1) + utils.force_case(".binary") + ' "' + binary_filepath + '"'
