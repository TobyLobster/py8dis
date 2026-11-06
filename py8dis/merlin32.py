"""
Merlin 32 assembler

Writes the output for Merlin 32 (Brutal Deluxe's cross-assembler, in the
syntax of the Apple II's Merlin 8 and 16: https://brutaldeluxe.fr/products/
crossdevtools/merlin), for the 6502 and the 65C02, which it assembles
without being told, and the 6510 (the 6502 with its undocumented opcodes,
which Merlin 32 doesn't know, so they're written as data). Merlin 32 writes
the program to a file named after the source file, without its extension,
in the same folder (with '_FileInformation.txt', ProDOS's information about
it, beside it).

Its syntax: a label starts in the first column, and anything else is
indented; ';' starts a comment; 'EQU' defines a constant; '$' starts a hex
number and '%' a binary one; 'DFB' and 'DA' are bytes and words, and 'ASC'
a string (in single quotes, or in double quotes for high ASCII, with bit 7
set); 'ORG' sets the address, and 'DS' reserves space.

What py8dis writes for it:

- Expressions: Merlin 32 works them out strictly from left to right
  ('2+3*4' is 20), so every binary operator binds as tightly as every other
  (see binary_precedence()), and they're grouped with '{' and '}', not
  brackets. AND, OR and EOR are '&', '.' and '!'. It has no MOD, NOT or
  shifts: py8dis stops with an error for MOD, as for xa, NOT is an EOR with
  $FFFFFFFF, and a shift by a number is a multiplication or division (see
  binary_rewrite()). The low and high byte operators, '<' and '>', apply to
  the whole of the rest of the operand, and can only start it, so in a
  larger expression they're written with '&' and '/' (see
  unary_rewrite()).

- 'ORG' sets the address the code is assembled for, but the bytes still
  follow on in the output, so a gap before a later range of addresses is
  padded with 'DS', and a moved block (see move()) is just an 'ORG' with
  its runtime address, then another back to its binary address after it,
  as for ca65.

- An absolute instruction with an operand in zero page is forced with ':'
  after the mnemonic (e.g. 'lda: addr,x'). Merlin 32 takes a label defined
  in the code to be an absolute address, even after it's defined, so a zero
  page label that a zero page instruction uses is always defined at the top
  (see zero_page_labels_first), with two hex digits (see hex4()). In an
  address operand, Merlin 32 takes '<' to force zero page addressing and
  '>' to force the 65816's long addressing, so an address operand that
  starts with '>', the high byte, is written with '&' and '/' instead (see
  operand_text()).

- A branch whose target wraps round the top or bottom of memory can't be
  written at all, so it's written as data bytes, with the offset worked out
  from the target's label, and the branch in a comment, e.g. 'dfb $30,
  {l0020-*-2} & $ff ; bmi l0020 (a branch that wraps round memory)'.

- Strings: ASCII is 'ASC' in single quotes, and the Apple II's high ASCII
  'ASC' in double quotes (which sets bit 7 of each character). A string
  can't contain its quote (a doubled quote isn't taken as one), so that's a
  number, as are the bytes that aren't characters; Merlin 32 reads those as
  hex, two digits each, so they're always written in hex (see
  string_number()). Character literals are e.g. 'A' (and "A" in high
  ASCII). Other encodings are written as bytes, with their text in a
  comment.

- The assertions at the end are 'ERR' lines, which stop Merlin 32 with an
  error if their expression isn't 0: 'ERR expression - value'.

- Merlin 32 takes a ';' straight after an operand to be part of it, so a
  line that reaches the inline comments' column has a space before its
  comment (see inline_comment_needs_space).

- Merlin 32 doesn't accept a register's name ('a', 'x' or 'y') as a label,
  so py8dis stops with an error for one (see _check_name()).
"""

import os
import re

import config
import expression
import session
import utils
import assembler

# The characters Merlin 32 doesn't accept in a character literal (in either
# quotes), e.g. "lda #','" (it's measured: they're all right in a string)
_NOT_CHAR_LITERALS = ",{}"

class Merlin32(assembler.Assembler):
    """This class encapsulates Merlin 32's syntax and features. (Tested with
    Merlin 32 v1.1.10. See assembler.Assembler for what each method is
    for.)"""

    # (See assembler.Assembler)
    zero_page_labels_first = True
    inline_comment_needs_space = True

    def __init__(self):
        super().__init__()

    def get_name(self):
        """'merlin32'."""
        return "merlin32"

    def cpus_supported(self):
        """The 6502, 65C02 and 6510 (whose undocumented opcodes are written
        as data)."""
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """A byte in hex, e.g. $1f."""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """A hex number for an address or a word: with two digits up to $ff
        (e.g. $1f), otherwise four (e.g. $1234)."""
        # Merlin 32 takes a label defined as e.g. '$001f' to be an absolute
        # address, so an instruction with only zero page addressing modes
        # (e.g. 'sty zp,x') can't use it, and an instruction that has an
        # absolute version is a byte longer in its first pass (so code near
        # the top of memory is too long for it). (It chooses zero page or
        # absolute addressing from a number's value, not how it's written,
        # so a number in an operand would be all right either way.)
        if n <= 0xff:
            return self.hex2(n)
        return "${0}".format(utils.plainhex4(n))

    def _address(self, n):
        """An address for 'ORG' or 'DS', with four hex digits, e.g. $0070."""
        return "${0}".format(utils.plainhex4(n))

    def hex(self, n):
        """A hex number, with two digits up to $ff (e.g. $1f), otherwise
        four (as hex4())."""
        return self.hex4(n)

    def binary_operators(self):
        """'.' for OR, '&' for AND, '!' for EOR, '/' for DIV, and '=' and '#'
        for '==' and '!='. There's no MOD, so py8dis stops with an error
        for it."""
        # 'generic name: assembler specific name'
        return { 'OR': '.',
                  '|': '.',
                'AND': '&',
                  '&': '&',
                'EOR': '!',
                'XOR': '!',
                  '^': '!',
                'DIV': '/',
                  '/': '/',
                'MOD': None,
                  '%': None,
                 '==': '=',
                 '!=': '#',
        }

    def binary_precedence(self):
        """Every binary operator at one level, since Merlin 32 works
        expressions out strictly from left to right."""
        # Measured with Merlin 32 v1.1.10: '2+3*4' is 20, so 'a + b * c' needs
        # '{' and '}' round 'b * c', but '(a + b) * c' needs nothing. With
        # every operator at one level, expression.py brackets a right hand
        # operand that has operators of its own (unless they're the same
        # associative operator), and never a left hand one.
        return { op: 6 for op in ('*', 'DIV', '+', '-', 'AND', 'OR', 'EOR', '==', '!=') }

    def unary_precedence(self):
        """'<' and '>' apply to the whole of the rest of the operand."""
        # Measured: '<lab+1' is the low byte of lab+1, so they bind less
        # tightly than any binary operator
        return { '<': 0, '>': 0 }

    def unary_rewrite(self, op, operand, nested):
        """NOT x as 'x ! $FFFFFFFF', and a low or high byte in a larger
        expression as 'x & $ff' or 'x & $ffff / $100'."""
        # Merlin 32 has no NOT; its numbers are 32 bits
        if op == 'NOT':
            return expression.Binary(operand, 'EOR', expression.Num(0xffffffff, "hex"))
        # '<' and '>' can only start an operand (not even in '{' and '}')
        if nested and op == '<':
            return expression.Binary(operand, 'AND', expression.Num(0xff, "hex"))
        if nested and op == '>':
            # (Merlin 32's '/' is signed, so the AND comes first, for a
            # negative number)
            return expression.Binary(expression.Binary(operand, 'AND', expression.Num(0xffff, "hex")), 'DIV', expression.Num(0x100, "hex"))
        return None

    def binary_rewrite(self, op, left, right, nested):
        """A shift by a number as a multiplication or division by a power of
        2, e.g. 'x * $100' for 'x << 8' (Merlin 32 has no shift operators).
        py8dis stops with an error for a shift by anything else."""
        if op not in ('<<', '>>'):
            return None
        count = right.evaluate(lambda name: None)
        if count is None or not 0 <= count < 32:
            utils.die("Merlin 32 has no shift operators, so a shift by '{0}' can't be written for it".format(right))
        factor = expression.Num(1 << count, "hex" if count >= 4 else "decimal")
        return expression.Binary(left, '*' if op == '<<' else 'DIV', factor)

    def expression_brackets(self):
        """'{' and '}'."""
        return ("{", "}")

    def _check_name(self, name):
        """Stops with utils.die() if Merlin 32 doesn't accept the name as a
        label: a register's name, 'a', 'x' or 'y' (in any case)."""
        # Measured: a label named 'a' is taken to be the accumulator in e.g.
        # 'lda a', and one named 'x' or 'y' replaces the index register in
        # e.g. 'lda table,x'
        name = str(name)
        if name.lower() in ("a", "x", "y"):
            utils.die("Merlin 32 doesn't accept '{0}' as a label, since it's a register's name: rename it".format(name))

    def inline_label(self, name):
        """Returns the string for defining a label in the first column: the
        name alone (checked, see _check_name())."""
        self._check_name(name)
        return str(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label EQU value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at 'EQU'. (The name is checked, see
        _check_name().)"""
        self._check_name(name)
        return "%s%s %s%s" % (utils.tab_to(name + " ", align_column), utils.force_case("EQU"), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """';'."""
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: how to
        assemble it."""
        c = self.comment_prefix()
        return [
            c + " Assemble with Merlin 32, which writes the program to a file named after",
            c + " this one without its extension, in the same folder:",
            c + "     merlin32 this_file.asm",
            "",
        ]

    def operand_text(self, prefix, operand):
        """An address operand (not an immediate one) that starts with '>'
        (the high byte) written with '&' and '/', since there '>' would make
        Merlin 32 use the 65816's long addressing."""
        # (In an address operand, Merlin 32 takes '<' to force zero page
        # addressing, keeping the low byte, which is what it means anyway,
        # and '>' to force long addressing)
        if prefix != "#" and operand.startswith(">"):
            return self._high_byte_text(operand[1:])
        return operand

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: 'ORG $2000', after 'DS' to pad a gap before a later
        range."""
        # ('ORG' sets the address, but the bytes still follow on in the
        # output, so a gap after the code before needs padding)
        result = [""]
        if not first:
            result.append("%s%s %s-*" % (utils.make_indent(1), utils.force_case("DS"), self._address(start_addr)))
        return result + ["%s%s %s" % (utils.make_indent(1), utils.force_case("ORG"), self._address(start_addr)), ""]

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: 'ORG' with the runtime address."""
        # (The bytes follow on in the output, so 'ORG' does this)
        return [utils.make_indent(1) + utils.force_case("ORG") + " " + self._address(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        """'ORG' with the binary address after the block."""
        return [utils.make_indent(1) + utils.force_case("ORG") + " " + self._address(source + length), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly, as 'ERR' lines:
        'ERR expression - value' stops Merlin 32 with an error unless it's 0.
        (An assertion of a string's value can't be written, so it's left
        out.)"""
        result = []
        if config.get_include_assertions():
            items = sorted(((str(expr), value, expr) for expr, value in self.pending_assertions.items() if type(value) == int), key=lambda item: (item[0], item[1]))
            old = None
            for text, value, expr in items:
                # (The same expression can be used at more than one address)
                if old != (text, value):
                    result.append("%s%s %s" % (utils.make_indent(1), utils.force_case("ERR"), self._check_text(expr, value)))
                old = (text, value)
        return result

    def _bracketed(self, text):
        """The expression 'text' in '{' and '}', unless it's a name or a
        number, or it's already in them."""
        if re.fullmatch(r"[A-Za-z0-9_$%]+", text) or expression.is_fully_bracketed(text):
            return text
        return "{%s}" % text

    def _high_byte_text(self, text):
        """The high byte of the expression 'text', written with '&' and '/',
        e.g. '{text} & $ffff / $0100'."""
        # (As in unary_rewrite())
        return "%s & %s / %s" % (self._bracketed(text), self.hex4(0xffff), self.hex4(0x100))

    def _check_text(self, expr, value):
        """The expression for an assertion that 'expr' has the value 'value':
        the expression minus the value, which is 0 if it's right."""
        # Merlin 32 works expressions out from left to right, so the
        # expression's text followed by ' - value' is right, unless it starts
        # with '<' or '>', which apply to the whole of the rest of the
        # operand (even the ' - value'), so they're written with '&' and '/'.
        # (This is done on the text, since a user's expression string can
        # start with them too.) A negative value is added.
        text = expression.render(expr, expression.ASSERTION)
        if text.startswith("<"):
            text = "%s & %s" % (self._bracketed(text[1:]), self.hex2(0xff))
        elif text.startswith(">"):
            text = self._high_byte_text(text[1:])
        return "%s %s %s" % (text, "-" if value >= 0 else "+", self.hex(abs(value)))

    def uses_current_address(self, text):
        """True if the text has '*' (the current address) where a number or
        a name would be, outside its character literals."""
        # (Otherwise '*' is multiplication, between two operands)
        text = re.sub(r"'[^']*'|\"[^\"]*\"", "", text)
        return re.search(r"(^|[-+*/&.!=<>#{,])\s*\*", text) is not None

    def wrapped_branch_operand(self, label, offset):
        """None: Merlin 32 can't write a branch that wraps round the top or
        bottom of memory, in any form, so it's written as data (see
        wrapped_branch_offset())."""
        return None

    def wrapped_branch_offset(self, label):
        """The offset worked out from the label, e.g. '{label-*-2} & $ff'
        ('*' is the address of the data's first byte, the branch's)."""
        return utils.LazyString("{%s-*-2} & %s", label, self.hex2(0xff))

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        """':' after the mnemonic, e.g. 'lda: addr,x'."""
        return "%s%s: %s%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def force_zp_label_prefix(self):
        """'<' (the low byte)."""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def byte_prefix(self):
        """'DFB '."""
        return utils.force_case("DFB ")

    def word_prefix(self):
        """'DA '."""
        return utils.force_case("DA ")

    def string_prefix(self):
        """'ASC '."""
        return utils.force_case("ASC ")

    # Text encodings: ASCII and high ASCII have 'ASC' (in single and double
    # quotes); other encodings are written as bytes.

    def text_directive(self, encoding):
        """'ASC ' for ASCII and the Apple II's high ASCII; None (so it's
        written as bytes) for any other."""
        if encoding.name == "ascii" or encoding.ascii_xor == 0x80:
            return self.string_prefix()
        return None

    def string_expression_directive(self, directive, length):
        """'DFB ' for one byte, since 'ASC' can't take an expression;
        otherwise as usual."""
        if length == 1:
            return self.byte_prefix()
        return super().string_expression_directive(directive, length)

    def string_quote(self, encoding):
        """"'" for ASCII, '"' for high ASCII (which sets bit 7)."""
        return "'" if encoding.name == "ascii" else '"'

    def string_quote_literal(self, n, encoding):
        """None: a string's quote is written as a number (see
        string_number())."""
        return None

    def text_chr(self, n, encoding):
        """The character for the byte, if it has one and it isn't the
        string's quote."""
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        return None if c in (None, '"') else c

    def string_number(self, binary_addr, encoding):
        """The byte at binary_addr in hex, with two digits (e.g. $0d),
        rather than as other data."""
        # Measured: Merlin 32 reads the numbers after a string as hex, as in
        # 'HEX' ('12' is $12, '1234' two bytes), so a number has two hex
        # digits, and an expression or a constant's name can't be used (a
        # name is replaced by its value, written as it's defined, so 'cr' is
        # $13 if 'cr EQU 13')
        import memorymanager
        return self.hex2(memorymanager.get_u8_binary(binary_addr))

    def encoded_char_literal(self, n, encoding):
        """A character literal: 'A' in ASCII, or "A" in high ASCII (which
        sets bit 7)."""
        if encoding.name == "ascii":
            return self.char_literal(n)
        if encoding.ascii_xor == 0x80:
            c = encoding.char(n)
            if c is not None and c not in _NOT_CHAR_LITERALS and c != '"':
                return '"' + c + '"'
        return None

    def char_literal(self, n):
        """A printable character in single quotes, except a single quote, a
        comma, '{' and '}'."""
        # ("'''" isn't accepted, and a doubled quote isn't taken as one)
        if utils.isprint(n) and chr(n) not in _NOT_CHAR_LITERALS and n != ord("'"):
            return "'" + chr(n) + "'"
        return None

    def string_chr(self, n):
        """A printable character as it is, except a single quote (the
        string's quote)."""
        if n == ord("'"):
            return None
        if utils.isprint(n):
            return chr(n)
        return None

    def binary_format(self, s):
        """'%' then the digits, e.g. %00101100."""
        return "%" + s

    def picture_binary(self, s):
        """The binary digits as they are."""
        # Merlin 32 has no way to write a 'picture' of the bits
        return s

    def sanitise_line(self, s):
        """The line as it is."""
        return s

    def supports_signed_integers(self):
        """True ('DFB -1')."""
        return True

    def include_binary_file(self, binary_filepath):
        """'PUTBIN file', with the path relative to the asm file's folder (if
        the output is written to a file)."""
        # Merlin 32 finds the file relative to the source file, so the path
        # (from the folder py8dis is run in) is made relative to the asm
        # file's folder, when it's written to a file, as for Baron
        asm_filename = session.current().asm_filename
        if asm_filename:
            binary_filepath = os.path.relpath(binary_filepath, os.path.dirname(os.path.abspath(asm_filename)))
            binary_filepath = binary_filepath.replace(os.sep, "/")
        return utils.make_indent(1) + utils.force_case("PUTBIN") + " " + binary_filepath
