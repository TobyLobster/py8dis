"""
z88dk assembler (z88dk-z80asm), for the 8080 (with -m8080) or the Z80 (with
-mz80)

Writes the output for z88dk-z80asm, the assembler from z88dk
(https://z88dk.org). (On the command line it's --z88dk, or --z88dk-8080, its
name from before the Z80 was added.)

Its syntax: 'name:' defines a label, 'name EQU value' a value, '$' starts a
hex number and on its own is the current address, 'DB' and 'DW' are the
data directives, and the operators are C's ('~' for NOT), except that '|'
and '^' bind equally tightly.

What py8dis writes for it:

- It has no low and high byte operators, so they're written with '&' and
  '>>' (see unary_rewrite()).

- An operand that starts with a bracket gets a unary plus, so that it isn't
  taken to be a memory access, e.g. 'ld b,+(count+1)*2' (see
  expression_in_context()).

- A moved block (see move()) is in a PHASE ... DEPHASE block. A later range
  of addresses is padded with DEFS, rather than given a second ORG (see
  code_start()), and a PRG file's header isn't written (see prg_header()).

- It has no assertions, so those at the end are comments.

- For the Z80, it accepts some of the undocumented instructions (see
  undocumented_z80_accepted()); the others are written as data bytes.

- A relative jump whose target wraps round the top or bottom of memory is
  given relative to the jump, e.g. '$-16'.

sjasmplus.py's Sjasmplus class is derived from this one.
"""

import re

import config
import expression
import utils
import assembler

class Z88DK(assembler.Assembler):
    """This class encapsulates z88dk-specific syntax and features. (See
    assembler.Assembler for what each method is for.)"""

    def __init__(self):
        super().__init__()

    def get_name(self):
        """'z88dk'."""
        return "z88dk"

    def cpus_supported(self):
        """The 8080 and the Z80."""
        return ["8080", "z80"]

    def undocumented_z80_accepted(self, kind):
        """The index registers' halves, SLL, the indexed CB instructions
        that also copy the result to a register, 'in f,(c)' and 'out
        (c),0'."""
        # (Checked with z88dk-z80asm v2.4, -mz80. It doesn't accept the
        # duplicates, e.g. 'neg' for ED 4C.)
        return kind in ("index_halves", "sll", "indexed_cb_register", "in_f_c", "out_c_0")

    def hex2(self, n):
        """A byte in hex, e.g. $1f."""
        return "$%s" % utils.plainhex2(n)

    def hex(self, n):
        """A hex number, with two digits up to $ff (e.g. $1f), otherwise
        four."""
        if n <= 0xff:
            return self.hex2(n)
        else:
            return "$%s" % utils.plainhex4(n)

    def hex4(self, n):
        """As hex(): four digits only for a value above $ff."""
        # Normally this would output four digits of hex, but like acme's
        # hex4() it only uses four when it needs to. (acme's reason, that
        # an address written with four digits is taken not to be in zero
        # page, is the 6502's: the 8080 and Z80 have no zero page.)
        return self.hex(n)

    def binary_operators(self):
        """C's: '|', '&', '^', '/' and '%'."""
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
        """NOT is '~'."""
        # 'generic name: assembler specific name'
        # Note: in z88dk-z80asm '!' is logical NOT, '~' is bitwise NOT
        return { 'NOT': '~',
                   '!': '~',
        }

    def binary_precedence(self):
        """As C's, except that OR and EOR bind equally tightly."""
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
        """NOT ('~') binds more tightly than any binary operator. (The low
        and high byte are rewritten, see unary_rewrite().)"""
        return { 'NOT': 90 }

    def unary_rewrite(self, op, operand, nested):
        """The low and high byte as 'x & $ff' and 'x >> 8'."""
        # z88dk-z80asm has no '<' and '>' (low and high byte) operators
        if op == '<':
            return expression.Binary(operand, 'AND', expression.Num(0xff, "hex"))
        if op == '>':
            return expression.Binary(operand, '>>', expression.Num(8))
        return None

    def expression_in_context(self, expr, text, level, context):
        """A unary plus before an instruction's operand that starts with a
        bracket; otherwise the text as it is."""
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

    def uses_current_address(self, text):
        """True if the text has '$' on its own (see below)."""
        # '$' on its own (not a hex number's '$', nor in a character literal
        # or string, e.g. "$80 + '$'") is the current address
        text = re.sub(r"'(\\.|[^'])*'|\"(\\.|[^\"])*\"", "", text)
        return re.search(r"\$(?![0-9A-Fa-f])", text) is not None

    def wrapped_branch_operand(self, label, offset):
        """Relative to the jump's address, e.g. '$-16'."""
        # z88dk-z80asm doesn't wrap a relative jump's target, but takes an
        # address past the top or bottom of memory, so give it relative to
        # the jump
        return "${0:+d}".format(offset)

    def inline_label(self, name):
        """Returns the string for defining a label in the first column:
        'name:'."""
        return "{0}:".format(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label EQU value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the EQU."""
        return "%s%s %s%s" % (utils.tab_to(name + " ", align_column), utils.force_case("EQU"), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """';'."""
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: nothing."""
        return []

    def prg_header(self, load_addr):
        """None: a PRG file's header isn't written (the default would need a
        second ORG)."""
        # (A second org would start a separate section)
        return None

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble. A later range (e.g. from another load()) is padded to its
        address with DEFS, since z88dk-z80asm doesn't allow a second ORG.
        (The padding is a number: in DEFS's operand, '$' and labels are
        offsets from the start of the section, not addresses.)"""
        if not first and previous_end is not None and start_addr > previous_end:
            return ["", "%s%s %d %s (to %s)" % (utils.make_indent(1), utils.force_case("DEFS"), start_addr - previous_end, self.comment_prefix(), self.hex4(start_addr)), ""]
        return ["", "%s%s %s" % (utils.make_indent(1), utils.force_case("ORG"), self.hex4(start_addr)), ""]

    def code_end(self):
        """Nothing."""
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: z88dk-z80asm's PHASE, which assembles the code
        that follows for the given address."""
        return [utils.make_indent(1) + utils.force_case("PHASE") + " " + self.hex(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        """'DEPHASE', ending the PHASE block."""
        return [utils.make_indent(1) + utils.force_case("DEPHASE"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly, as comments
        ('; ASSERT ((expr) == value)'), since z88dk-z80asm has no assertions
        of its own. (So they aren't checked.)"""
        result = []

        if config.get_include_assertions():
            spa = sorted((str(expr), self.assertion_value(value)) for expr, value in self.pending_assertions.items())
            old = None
            for expr, value in spa:
                # (The same expression can be used at more than one address)
                if old != (expr, value):
                    result.append("; ASSERT ((%s) == %s)" % (expr, value))
                old = (expr, value)

        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        """'!' before the operand. (Never used: forcing absolute addressing
        is for the 6502's zero page, and z88dk-z80asm is only used for the
        8080 and Z80.)"""
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda !addr,x'
        return "%s%s !%s%s%s" % (utils.make_indent(1), instruction, prefix, operand, suffix)

    def force_zp_label_prefix(self):
        """No prefix (an empty string). (Only for the 6502, as
        force_abs_instruction().)"""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return ""

    def byte_prefix(self):
        """'DB '."""
        # For outputting bytes
        return utils.force_case("DB ")

    def word_prefix(self):
        """'DW '."""
        # For outputting words
        return utils.force_case("DW ")

    def string_prefix(self):
        """'DB ', which takes strings too."""
        # For outputting strings
        return utils.force_case("DB ")

    def string_chr(self, i):
        """A printable character, with a backslash before a backslash or a
        double quote."""
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible
        if i == ord('\\'):
            return '\\\\'
        if i == ord('"'):
            return '\\"'
        if utils.isprint(i):
            return chr(i)
        return None

    def char_literal(self, n):
        """A printable character in single quotes, with a backslash before a
        backslash or a single quote."""
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible. (Checked with
        # z88dk-z80asm: '\\' and '\'' are escaped.)
        if n == ord('\\'):
            return "'\\\\'"
        if n == ord("'"):
            return "'\\''"
        if utils.isprint(n):
            return "'" + chr(n) + "'"
        return None

    def binary_format(self, s):
        """'%' then the digits, e.g. %00101100."""
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        """'%"' then '-' for each 0 and '#' for each 1, then '"', e.g.
        %"--#-##--"."""
        # Converts a string of '0' and '1's into '-' and '#'s for visualising
        # data (taking off binary_format()'s '%')
        return "%\"" + s.replace("0", "-").replace("1", "#").replace("%", "") + "\""

    def sanitise_line(self, s):
        """The line as it is."""
        return s

    def supports_signed_integers(self):
        """True."""
        return True

    def include_binary_file(self, binary_filepath):
        """'BINARY "file"'."""
        return utils.make_indent(1) + utils.force_case("BINARY") + ' "' + binary_filepath + '"'
