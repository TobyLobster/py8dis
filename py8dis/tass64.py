"""
64tass assembler

Writes the output for 64tass (https://sourceforge.net/projects/tass64/), for
the 6502, the 65C02 and the 6510 (the 6502 with its undocumented opcodes).
The output is assembled with '64tass -b', which writes a plain binary,
without the load address 64tass writes by default (a PRG file's comes from
the default prg_header(), as for most assemblers).

Its syntax: a label is defined by its name alone, '$' starts a hex number,
'.byte', '.word' and '.text' are the data directives, the operators are C's
('~' for NOT), and '<' and '>' (low and high byte) apply to the whole of the
rest of an expression.

What py8dis writes for it:

- The output starts with '.cpu "65c02"' for the 65C02, or '.cpu "6502i"' for
  the 6510, whose undocumented opcodes 64tass assembles (but for an
  instruction with several opcodes, only one, as acme).

- An absolute instruction with an operand in zero page is forced with '@w'
  (e.g. 'lda @w addr,x'). A moved block (see move()) is in '.logical' ...
  '.here'. The assertions at the end use '.cerror'.

- Text: '.text' and character literals use the encoding selected with
  '.enc'. If the output has text in PETSCII or screen codes, it starts by
  defining encodings for them with '.cdef', and selects the session's
  encoding; a string in another encoding selects its own just for that
  string. (See the comments before _main_encoding().)

- 64tass takes a label starting with '_' to be local to the label before
  it, so py8dis stops with an error for one.

- A data byte or word can't be negative, so sint() is written unsigned.
"""

import re

import config
import session
import utils
import assembler
import cpu6510
import textencoding

# The names of the encodings the output defines for PETSCII, screen codes and
# the Apple II's high ASCII (not 64tass's own 'screen', which '64tass -a'
# changes, as it does 'none', which is ASCII without it)
_ENCODING_NAMES = {"ascii": "none", "petscii": "petscii", "screen": "screencodes", "apple": "apple"}

class Tass64(assembler.Assembler):
    """This class encapsulates 64tass-specific syntax and features. (Tested
    with 64tass 1.59.3120: the output is assembled with '64tass -b', which
    writes a plain binary, without a load address. See assembler.Assembler
    for what each method is for.)"""

    def __init__(self):
        super().__init__()
        # 64tass accepts 'rol' for 'rol a', but not 'inc' for the 65C02's
        # 'inc a', so the A is always given
        self.explicit_a = True

    def get_name(self):
        """'64tass'."""
        return "64tass"

    def cpus_supported(self):
        """The 6502, 65C02 and 6510."""
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """A byte in hex, e.g. $1f."""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """A four digit hex number, e.g. $001f."""
        # (64tass chooses zero page or absolute addressing from an operand's
        # value, not how it's written, so '$0012' is zero page)
        return "${0}".format(utils.plainhex4(n))

    def hex(self, n):
        """A hex number, with two digits up to $ff (e.g. $1f), otherwise
        four."""
        if n <= 0xff:
            return self.hex2(n)
        return self.hex4(n)

    def binary_operators(self):
        """C's: '|', '&', '^', '/' and '%'."""
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
        """As C's."""
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
        """'<' and '>' bind less tightly than anything else, NOT more
        tightly."""
        # In 64tass '<' and '>' (low and high byte) apply to the whole of the
        # rest of the expression, e.g. '>ab+$100' is '>(ab+$100)' and even
        # '>ab==$12' is '>(ab==$12)', so they bind less tightly than anything
        # else (as in xa). '~' (NOT) binds tightly: '~1+3' is 1.
        return { '<': 0, '>': 0, 'NOT': 90 }

    def unary_operators(self):
        """NOT is '~'."""
        # 'generic name: assembler specific name'
        return { 'NOT': '~',
                   '!': '~',
        }

    def _check_name(self, name):
        """Stops with utils.die() for a name starting with '_'."""
        # 64tass takes a label starting with '_' to be a 'cheap local' label,
        # which can't be used after the next label
        if str(name).startswith("_"):
            utils.die("64tass takes a label starting with '_' to be local to the label before it, so '{0}' can't be used: rename it".format(name))

    def inline_label(self, name):
        """Returns the string for defining a label in the first column: the
        name alone (checked, see _check_name())."""
        self._check_name(name)
        return name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign. (The name is checked, see
        _check_name().)"""
        self._check_name(name)
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """';'."""
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: '.cpu' for
        the 65C02 or the 6510, then the text encodings (see
        _encoding_definitions())."""
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
        # The encodings of the strings, and the session's, if it has
        # strings or character literals (from char()) in it
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
        """The '.enc' line that selects the encoding (by the output's name for
        it, see _ENCODING_NAMES)."""
        return '%s%s "%s"' % (utils.make_indent(1), utils.force_case(".enc"), _ENCODING_NAMES[encoding_name])

    def _cdef_lines(self, encoding):
        """'.cdef' lines defining the encoding's characters: each run of
        characters with consecutive codes, whose bytes are consecutive too
        (e.g. '.cdef "az", $41')"""
        # (Each run is [first character's code, last character's code, first
        # byte])
        pairs = sorted((ord(char), byte) for byte, char in encoding.chars.items())
        runs = []
        for code, byte in pairs:
            if runs and runs[-1][1] == code - 1 and runs[-1][2] == byte - (code - runs[-1][0]):
                runs[-1][1] = code
            else:
                runs.append([code, code, byte])

        def quoted(text):
            """The text as a 64tass string: in double quotes, or in single
            quotes if it has a double quote in it."""
            # (A string can be in either kind of quote; inside it, its own
            # kind is doubled)
            quote = "'" if '"' in text else '"'
            return quote + text.replace(quote, quote * 2) + quote

        return ["%s%s %s, %s" % (utils.make_indent(1), utils.force_case(".cdef"), quoted(chr(first) + chr(last)), self.hex2(byte))
                for first, last, byte in runs]

    def text_encoding_lines(self, encoding):
        """For a string in another encoding than the main one, '.enc' lines
        to select it, then the main one again."""
        # A string in an encoding other than the main one selects its own
        # encoding, then the main one again
        main = self._main_encoding()
        if encoding.name == main.name:
            return [], []
        return [self._enc_line(encoding.name)], [self._enc_line(main.name)]

    # An '.enc' line (see _enc_line()), with the encoding's name as group 1
    _ENC_LINE = re.compile(r'^\s*\.enc "([^"]*)"\s*$', re.IGNORECASE)

    def tidy_output(self, lines):
        """The lines without the '.enc' lines that change nothing."""
        # Strings in other encodings than the main one each select their own,
        # then the main one again (see text_encoding_lines()), so for two in
        # a row there are lines that change nothing: the main encoding
        # selected just before another, or an encoding selected when it
        # already is. Leave those out.
        result = []
        current = None      # (The encoding selected so far)
        for i, line in enumerate(lines):
            m = self._ENC_LINE.match(line)
            if m is not None:
                # (Another '.enc' straight after this one replaces it)
                if i + 1 < len(lines) and self._ENC_LINE.match(lines[i + 1]):
                    continue
                if m.group(1) == current:
                    continue
                current = m.group(1)
            result.append(line)
        return result

    def text_directive(self, encoding):
        """'.text ', for every encoding (see above)."""
        return utils.force_case(".text ")

    def text_chr(self, n, encoding):
        """The encoding's character for the byte (None if it has none), with
        a double quote doubled."""
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        if c == '"':
            return '""'
        return c

    def encoded_char_literal(self, n, encoding):
        """A character literal, only in the main encoding: e.g. 'a', or "'"
        for a single quote."""
        # Only in the main encoding (see above)
        if encoding.name != self._main_encoding().name:
            return None
        if encoding.name == "ascii":
            return self.char_literal(n)
        c = encoding.char(n)
        if c is None:
            return None
        return '"\'"' if c == "'" else "'" + c + "'"

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: '* = $2000'."""
        return ["", "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)), ""]

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: '.logical' with the runtime address."""
        return [utils.force_case(".logical %s" % self.hex(dest))]

    def pseudopc_end(self, dest, source, length, move_id):
        """'.here', ending the '.logical' block."""
        return [utils.force_case(".here"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly, as '.cerror'
        lines."""
        result = []

        # 64tass's '.cerror condition, "message"' stops with the message if
        # the condition is true
        if config.get_include_assertions():
            spa = sorted((str(expr), self.assertion_value(value)) for expr, value in self.pending_assertions.items())
            old = ("", 0)
            for expr, value in spa:
                # (The same expression can be used at more than one address.
                # In the message, a string value's quotes are doubled.)
                if old != (expr, value):
                    result.append('%s (%s) != %s, "Assertion failed: %s == %s"' % (utils.force_case(".cerror"), expr, value, expr, value.replace('"', '""')))
                old = (expr, value)

        return result

    def undocumented_6502_opcodes(self):
        """cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES, as acme."""
        # With '.cpu "6502i"' 64tass assembles all the undocumented mnemonics
        # (with py8dis's names), but where an instruction has several opcodes
        # it uses only one, the same as acme (found by assembling each with
        # 64tass 1.59.3120), so the others are written as data.
        return cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        """'@w ' before the operand, e.g. 'lda @w addr,x'."""
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda @w addr,x'
        return "%s%s %s%s%s%s" % (utils.make_indent(1), instruction, prefix, utils.force_case("@w "), operand, suffix)

    def force_zp_label_prefix(self):
        """'<' (the low byte)."""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def byte_prefix(self):
        """'.byte '."""
        # For outputting bytes
        return utils.force_case(".byte ")

    def word_prefix(self):
        """'.word '."""
        # For outputting words
        return utils.force_case(".word ")

    def string_prefix(self):
        """'.text '."""
        # For outputting strings (64tass's default encoding, 'none', leaves
        # the bytes as they are)
        return utils.force_case(".text ")

    def char_literal(self, n):
        """A printable character in single quotes (a single quote in double
        quotes), only if the main encoding is ASCII."""
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
        """A printable character as it is, with a double quote doubled."""
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible. (A '"' is written '""';
        # a backslash is an ordinary character.)
        if n == ord('"'):
            return '""'
        if utils.isprint(n):
            return chr(n)
        return None

    def binary_format(self, s):
        """'%' then the digits, e.g. %00101100."""
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        """The binary digits as they are."""
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data. 64tass doesn't support this ('%..##' is an error).
        return s

    def sanitise_line(self, s):
        """The line as it is."""
        return s

    def supports_signed_integers(self):
        """False."""
        # '.byte -1' is an error ('value needs to be non-negative'), so don't
        # use signed integers
        return False

    def include_binary_file(self, binary_filepath):
        """'.binary "file"' (which 64tass looks for relative to the asm
        file, see docs/assemblers.md)."""
        return utils.make_indent(1) + utils.force_case(".binary") + ' "' + binary_filepath + '"'
