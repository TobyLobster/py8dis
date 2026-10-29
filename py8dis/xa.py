"""
XA assembler
"""

import sys

import config
import expression
import disassembly
import movemanager
import utils
import assembler

class Xa(assembler.Assembler):
    """This class encapsulates xa-specific syntax and features."""

    def __init__(self):
        super().__init__()

        # Numbers the labels that mark the end of each code block, see
        # code_start()
        self._code_index = 1

    def get_name(self):
        return "xa"

    def cpus_supported(self):
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """format a two digit hex number"""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """format a four digit hex number"""
        return "${0}".format(utils.plainhex4(n))

    def hex(self, n):
        """format a hex number"""
        if n <= 0xff:
            return self.hex2(n)
        else:
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
                'MOD': None,
                  '%': None,
                 '!=': '<>',
        }
    def binary_precedence(self):
        # Measured by assembling test expressions with xa 2.4.0
        return { '*': 7, 'DIV': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 4,
                 'EOR': 3,
                 'OR': 2,
        }

    def unary_precedence(self):
        # In xa '<' and '>' (low and high byte) can only appear at the start of
        # an operand, where they apply to the whole of the rest of it, i.e. they
        # bind less tightly than anything else. (See unary_rewrite() for when
        # they are part of a larger expression.)
        return { '<': 0, '>': 0 }

    def unary_rewrite(self, op, operand, nested):
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
        """Returns the string for defining a label in the first column."""
        return name

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        # NOTE: xa supports ";" as a comment prefix, but by default colons
        # terminate ";" comments, so we use "//".
        return "//"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly."""
        return []

    def code_start(self, start_addr, end_addr, first):
        """At the start of the code we provide the address at which to
        assemble."""
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
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute."""

        return ["* = %s" % self.hex(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        # (A literal address: xa won't accept a forward reference in
        # '* = ...', and a label for the end of the block can be defined
        # after this, e.g. by a later move.)
        return ["* = %s" % self.hex(source + length)]

    def expression_in_context(self, expr, text, level, context):
        if context == expression.PREPROCESSOR:
            # The preprocessor's '#if' doesn't understand the '<' and '>' (low
            # and high byte) operators, or the '`' (force zero page) operator.
            # In xa these can only appear at the start of an operand, where
            # they apply to the whole of the rest of the operand, so rewrite
            # them using '&' and '>>'. (This is done on the text, since a
            # user's expression string can start with these too.)
            def bracketed(t):
                return t if expression.is_fully_bracketed(t) else "(%s)" % t
            if text.startswith("<") or text.startswith("`"):
                return "(%s & $ff)" % bracketed(text[1:])
            if text.startswith(">"):
                return "((%s >> 8) & $ff)" % bracketed(text[1:])
            return bracketed(text)
        return text

    def disassembly_end(self):
        """Output assertions at the end of the disassembly"""
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
            for expr_text, value, expr in spa:
                result.append("%s %s <> %s" % (utils.force_case("#if"), expression.render(expr, expression.PREPROCESSOR), self.hex(value)))
                result.append("%s Assertion failed: %s == %s" % (utils.force_case("#error"), expr_text, self.hex(value)))
                result.append(utils.force_case("#endif"))

        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda !addr,x'

        # It's tempting to put brackets around "operand" in case it contains an
        # expression, but the "!" prefix operator doesn't seem to like this and
        # probably doesn't need it.
        return "%s%s %s!%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def direct_operand(self, operand):
        # xa takes an operand starting with a bracket to be indirect, so 'lda
        # (table+1) - 1,y' is an error. (Forcing absolute addressing, '!(...)',
        # isn't affected.)
        return "0+" + operand

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "`"

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case(".byt ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case(".word ")

    def string_prefix(self):
        # For outputting strings
        return utils.force_case(".asc ")

    def char_literal(self, n):
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
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data. Sadly xa does not support this.
        return s

    def sanitise_line(self, s):
        # xa uses "\" as a line continuation character, so if a line (e.g. an
        # ASCII dump of some byte data) happens to end with that, add a space to
        # stop it being misinterpreted.
        if len(s) > 0 and s[-1] == "\\":
            return s + " "
        return s

    def supports_signed_integers(self):
        # e.g. ".byt -2" is an error, so don't use signed integers
        return False

    def include_binary_file(self, binary_filepath):
        return utils.make_indent(1) + utils.force_case(".bin") + ' 0,0,"' + binary_filepath + '"'
