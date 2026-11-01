"""
XA assembler

Writes the output for xa (https://www.floodgap.com/retrotech/xa/), for the
6502, the 65C02 and the 6510 (the 6502 with its undocumented opcodes, which
are written as data bytes, with the instruction in a comment).

Its syntax: a label is defined by its name alone, '$' starts a hex number,
'.byt', '.word' and '.asc' are the data directives, and the operators are
mostly C's ('&', '|', '^', '/', '<>' for '!='). Comments start with '//',
since by default a colon ends a ';' comment. '<' and '>' (low and high byte)
can only start an operand, so elsewhere they're written with AND and '>>',
and NOT x is written '-1 - x', since xa has no bitwise NOT (see
unary_rewrite()). py8dis stops with an error for MOD. An absolute
instruction with an operand in zero page is forced with '!' (e.g. 'lda
!addr,x').

What py8dis writes for it:

- '* = ' sets the address to assemble at, and a moved block (see move()) is
  assembled by setting it to the block's runtime address, then back. A
  later range of addresses is padded to its address with '.dsb' (see
  code_start()).

- xa has no assert directive, so the assertions at the end use its
  preprocessor ('#if', '#error', '#endif'), and strings' values aren't
  checked.

- Some characters can't be written in a string or character literal,
  because of bugs in xa or differences between its versions, so they're
  written as numbers: '"', '^', '\\', '/' (and "'" in a character literal).

- A line that ends with a backslash gets a space after it (see
  sanitise_line()).

- A data byte or word can't be negative, so sint() is written unsigned.
"""

import sys

import config
import expression
import disassembly
import movemanager
import utils
import assembler

class Xa(assembler.Assembler):
    """This class encapsulates xa-specific syntax and features. (See
    assembler.Assembler for what each method is for.)"""

    def __init__(self):
        super().__init__()

        # Numbers the labels that mark the end of each code block, see
        # code_start()
        self._code_index = 1

    def get_name(self):
        """'xa'."""
        return "xa"

    def cpus_supported(self):
        """The 6502, 65C02 and 6510 (whose undocumented opcodes are written
        as data)."""
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """A byte in hex, e.g. $1f."""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """A four digit hex number, e.g. $001f."""
        return "${0}".format(utils.plainhex4(n))

    def hex(self, n):
        """A hex number, with two digits up to $ff (e.g. $1f), otherwise
        four."""
        if n <= 0xff:
            return self.hex2(n)
        else:
            return self.hex4(n)

    def binary_operators(self):
        """'|', '&', '^', '/', and '<>' for '!='. MOD isn't supported (None:
        py8dis stops with an error for it)."""
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
                'MOD': None,
                  '%': None,
                 '!=': '<>',
        }
    def binary_precedence(self):
        """As C's."""
        # Measured by assembling test expressions with xa 2.4.0
        return { '*': 7, 'DIV': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 4,
                 'EOR': 3,
                 'OR': 2,
        }

    def unary_precedence(self):
        """'<' and '>' bind less tightly than anything else."""
        # In xa '<' and '>' (low and high byte) can only appear at the start of
        # an operand, where they apply to the whole of the rest of it, i.e. they
        # bind less tightly than anything else. (See unary_rewrite() for when
        # they are part of a larger expression.)
        return { '<': 0, '>': 0 }

    def unary_rewrite(self, op, operand, nested):
        """NOT x as '-1 - x', and a low or high byte in a larger expression as
        'x AND $ff' or 'x >> 8'."""
        # xa has no bitwise NOT operator ('!' at the start of an operand forces
        # absolute addressing instead), so use the two's complement identity
        # NOT x == -1 - x
        if op == 'NOT':
            return expression.Binary(expression.Num(-1), '-', operand)
        # '<' and '>' can't be used in the middle of an expression (not even in
        # brackets), so there use AND and '>>' instead
        if nested and op == '<':
            return expression.Binary(operand, 'AND', expression.Num(0xff, "hex"))
        if nested and op == '>':
            return expression.Binary(operand, '>>', expression.Num(8))
        return None

    def inline_label(self, name):
        """Returns the string for defining a label in the first column: the
        name alone."""
        return name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """'//'."""
        # NOTE: xa supports ";" as a comment prefix, but by default colons
        # terminate ";" comments, so we use "//".
        return "//"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: nothing."""
        return []

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: '* = $2000'. A later range is padded to its address with
        '.dsb', after a label (end_of_part_1 etc) marking the end of the
        output before it."""
        # The first code block is just a "* = $xxxx" style line
        if first:
            self._code_index = 1
            return ["", "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)), ""]

        end_label = "end_of_part_" + str(self._code_index)
        self._code_index += 1

        # Subsequent blocks need weird code to pad with a '.dsb' command

        # Example from docs at http://www.floodgap.com/retrotech/xa/xa.1.html :
        #
        #     * = $1000
        #
        #     ; this is your code at $1000
        # part1       rts
        #     ; this label marks the end of code
        # endofpart1
        #
        #     ; DON'T PUT A NEW .word HERE!
        #     * = $2000
        #     .dsb (*-endofpart1), 0
        #     ; yes, set it again
        #     * = $2000
        #
        #     ; this is your code at $2000
        # part2       rts

        # So we mimic this example here:
        return [end_label,
            "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)),
            "%s (*-%s), 0" % (utils.force_case(".dsb"), end_label),
            "%s* = %s" % (utils.make_indent(1), self.hex4(start_addr)),
            ""]

    def code_end(self):
        """Nothing."""
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: '* = ' the runtime address. (Setting the address
        doesn't pad the output, see code_start(), so the block's bytes still
        follow on from those before it.)"""

        return ["* = %s" % self.hex(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        """'* = ' the binary address after the block."""
        # (A literal address: xa won't accept a forward reference in
        # '* = ...', and a label for the end of the block can be defined
        # after this, e.g. by a later move.)
        return ["* = %s" % self.hex(source + length)]

    def expression_in_context(self, expr, text, level, context):
        """For the preprocessor (an assertion's '#if'), a '<', '>' or '`' at
        the start rewritten with '&' and '>>', and the whole in brackets;
        otherwise the text as it is."""
        if context == expression.PREPROCESSOR:
            # The preprocessor's '#if' doesn't understand the '<' and '>' (low
            # and high byte) operators, or the '`' (force zero page) operator.
            # In xa these can only appear at the start of an operand, where
            # they apply to the whole of the rest of the operand, so rewrite
            # them using '&' and '>>'. (This is done on the text, since a
            # user's expression string can start with these too.)
            def bracketed(t):
                """The text t in brackets, unless it already is."""
                return t if expression.is_fully_bracketed(t) else "(%s)" % t
            if text.startswith("<") or text.startswith("`"):
                return "(%s & $ff)" % bracketed(text[1:])
            if text.startswith(">"):
                return "((%s >> 8) & $ff)" % bracketed(text[1:])
            return bracketed(text)
        return text

    def disassembly_end(self):
        """Output assertions at the end of the disassembly, with xa's
        preprocessor (see below): only those whose value is a number."""
        result = []

        # xa has no assert directive, so we use its preprocessor instead:
        #
        #     #if (expr) <> value
        #     #error Assertion failed: expr == value
        #     #endif
        #
        # At the end of the file all the labels have been defined, so the
        # preprocessor can evaluate expressions that use them.
        #
        # (xa doesn't support string constants, so string values are not checked.)
        if config.get_include_assertions():
            spa = sorted(((str(expr), value, expr) for expr, value in self.pending_assertions.items() if utils.is_integer_type(value)), key=lambda x: x[:2])
            old = None
            for expr_text, value, expr in spa:
                # (The same expression can be used at more than one address)
                if old == (expr_text, value):
                    continue
                old = (expr_text, value)
                result.append("%s %s <> %s" % (utils.force_case("#if"), expression.render(expr, expression.PREPROCESSOR), self.signed_hex(value)))
                result.append("%s Assertion failed: %s == %s" % (utils.force_case("#error"), expr_text, self.signed_hex(value)))
                result.append(utils.force_case("#endif"))

        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        """'!' before the operand, e.g. 'lda !addr,x'."""
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda !addr,x'

        # It's tempting to put brackets around "operand" in case it contains an
        # expression, but the "!" prefix operator doesn't seem to like this and
        # probably doesn't need it.
        return "%s%s %s!%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def direct_operand(self, operand):
        """'0+' before the operand, e.g. 'lda 0+(table+1) - 1,y'."""
        # xa takes an operand starting with a bracket to be indirect, so 'lda
        # (table+1) - 1,y' is an error. (Forcing absolute addressing, '!(...)',
        # isn't affected.)
        return "0+" + operand

    def force_zp_label_prefix(self):
        """'`', which forces zero page addressing."""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "`"

    def byte_prefix(self):
        """'.byt '."""
        # For outputting bytes
        return utils.force_case(".byt ")

    def word_prefix(self):
        """'.word '."""
        # For outputting words
        return utils.force_case(".word ")

    def string_prefix(self):
        """'.asc '."""
        # For outputting strings
        return utils.force_case(".asc ")

    def char_literal(self, n):
        """A printable character in single quotes, except a double or single
        quote, '^', a backslash or '/'."""
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        quote = "'"
        if chr(n) == '"':
            return None
        if chr(n) == '\'':
            return None
        if chr(n) == '^':
            return None
        if chr(n) == '\\':
            return None
        # xa has a bug which can affect strings containing '/', so we force them
        # to be encoded specially. See
        # https://stardot.org.uk/forums/viewtopic.php?p=351954#p351954 for more.
        if chr(n) == '/':
            return None
        if utils.isprint(n):
            return quote + chr(n) + quote
        return None

    def string_chr(self, n):
        """A printable character as it is, except '/' (None: written as a
        number), and a double quote, '^' and a backslash, which close the
        string's quotes, give the character's code and open them again, e.g.
        '", 34, "'."""
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible

        # Different versions of xa have different policies about which characters
        # can be freely expressed in a string. We work around this by encoding any
        # problematic characters as numbers.

        # Workaround for a bug in xa that means an escaped double quote in a
        # string doesn't play well with a // comment, causing a syntax error
        if chr(n) == '"':
            return "\", 34, \""
        if chr(n) == '^':
            return "\", 94, \""
        if chr(n) == '\\':
            return "\", 92, \""
        # xa has a bug which can affect strings containing '/', so we force them
        # to be encoded specially. See
        # https://stardot.org.uk/forums/viewtopic.php?p=351954#p351954 for more.
        if chr(n) == '/':
            return None
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
        # data. Sadly xa does not support this.
        return s

    def sanitise_line(self, s):
        """A space after a backslash at the end of the line."""
        # xa uses "\" as a line continuation character, so if a line (e.g. an
        # ASCII dump of some byte data) happens to end with that, add a space to
        # stop it being misinterpreted.
        if len(s) > 0 and s[-1] == "\\":
            return s + " "
        return s

    def supports_signed_integers(self):
        """False."""
        # e.g. ".byt -2" is an error, so don't use signed integers
        return False

    def include_binary_file(self, binary_filepath):
        """'.bin 0,0,"file"'."""
        return utils.make_indent(1) + utils.force_case(".bin") + ' 0,0,"' + binary_filepath + '"'
