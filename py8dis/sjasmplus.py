"""
sjasmplus assembler (https://github.com/z00m128/sjasmplus), for the Z80

Its syntax is mostly z88dk-z80asm's (C's operators, '$' for the current
address, the same undocumented instructions, and a unary plus
before an operand that starts with a bracket, so that it's a value rather
than a memory access), so this is z88dk.py's class with sjasmplus's
directives, low and high byte operators, character literals and checks on
label names. (Measured with sjasmplus v1.24.0: see the project's sjasmplus
plan.) It's for the Z80 only, since sjasmplus has no 8080 mnemonics.

What py8dis writes for it, beyond what z88dk.py does:

- The output starts with a comment saying how to assemble it to a plain
  binary (sjasmplus --raw).

- 'low x' and 'high x' are the low and high byte, and bind more tightly
  than any binary operator. The binary operators bind as in C (unlike
  z88dk-z80asm, where '|' and '^' bind equally tightly).

- A later range of addresses is padded with DS, then has an ORG of its own.
  A moved block (see move()) is a DISP ... ENT block.

- The assertions at the end are sjasmplus's ASSERT, which it checks.

- If the output uses 'out (c),0', it turns off sjasmplus's warning about it
  (see tidy_output()).

- A single quote can't be written in a character literal in single quotes
  (there are no escapes), so it's written "'".

- sjasmplus doesn't accept a register's or condition's name, one of its
  operators that's a word, or a name longer than 64 characters as a label,
  so py8dis stops with an error for one (see _check_name()).
"""

import re

import config
import utils
import z88dk

# Names sjasmplus takes to be something else in an operand (in any case), so
# it doesn't accept them as labels: the Z80's registers (and sjasmplus's
# other names for the index registers' halves), the conditions, and its
# operators that are words
_REGISTERS = set("""
    a b c d e h l i r f af bc de hl ix iy sp
    ixh ixl iyh iyl xh xl hx lx yh yl hy ly""".split())
_CONDITIONS = set("nz z nc c po pe p m".split())
_OPERATOR_KEYWORDS = set("and or xor mod low high not shl shr abs exist sizeof norel pair u16".split())

# sjasmplus's longest label name (LABMAX in its source)
_MAX_NAME_LENGTH = 64

class Sjasmplus(z88dk.Z88DK):
    """This class encapsulates sjasmplus-specific syntax and features. (See
    assembler.Assembler for what each method is for; those not here are
    z88dk.py's.)"""

    def get_name(self):
        """'sjasmplus'."""
        return "sjasmplus"

    def cpus_supported(self):
        """Only the Z80."""
        # (sjasmplus has no Intel 8080 mnemonics: its --i8080 only limits it
        # to the Z80 instructions the 8080 has)
        return ["z80"]

    def binary_precedence(self):
        """As C's."""
        # Measured by assembling test expressions with sjasmplus v1.24.0: C's
        # (e.g. '6&3+1' is 4, '1+2<<1' is 6, '1|6^3' is 5, '5^3&1' is 4)
        return { '*': 7, 'DIV': 7, 'MOD': 7,
                 '+': 6, '-': 6,
                 '<<': 5, '>>': 5,
                 'AND': 4,
                 'EOR': 3,
                 'OR': 2,
        }

    def unary_operators(self):
        """'low ' and 'high ' for the low and high byte, and '~' for NOT."""
        # 'low x' and 'high x' are the low and high byte; '~' is bitwise NOT
        return { 'NOT': '~',
                   '!': '~',
                   '<': utils.force_case("low "),
                   '>': utils.force_case("high "),
        }

    def unary_precedence(self):
        """'low', 'high' and NOT bind more tightly than any binary
        operator."""
        # 'low' and 'high' bind more tightly than any binary operator, so
        # 'high $1234+$100' is '(high $1234)+$100', as beebasm's '<' and '>'
        return { '<': 90, '>': 90, 'NOT': 90 }

    def unary_rewrite(self, op, operand, nested):
        """None: nothing is rewritten."""
        # (z88dk-z80asm writes the low and high byte with '&' and '>>', but
        # sjasmplus has 'low' and 'high')
        return None

    def _check_name(self, name):
        """Stops with utils.die() if sjasmplus doesn't accept the name as a
        label: a register's or condition's name, or one of its operators
        that's a word (in any case), or a name longer than
        _MAX_NAME_LENGTH."""
        name = str(name)
        lower = name.lower()
        if lower in _REGISTERS:
            what = "a register's name"
        elif lower in _CONDITIONS:
            what = "a condition's name"
        elif lower in _OPERATOR_KEYWORDS:
            what = "an operator's name"
        elif len(name) > _MAX_NAME_LENGTH:
            utils.die("sjasmplus doesn't accept '{0}' as a label, since it's longer than {1} characters: rename it".format(name, _MAX_NAME_LENGTH))
        else:
            return
        utils.die("sjasmplus doesn't accept '{0}' as a label, since it's {1}: rename it".format(name, what))

    def inline_label(self, name):
        """Returns the string for defining a label in the first column:
        'name:' (checked, see _check_name())."""
        self._check_name(name)
        return "{0}:".format(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        """'name EQU value', as z88dk-z80asm, checking the name (see
        _check_name())."""
        self._check_name(name)
        return super().explicit_label(name, value, offset, align_column)

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: how to
        assemble it."""
        c = self.comment_prefix()
        return [
            c + " Assemble with sjasmplus, to a plain binary:",
            c + "     sjasmplus --nologo --raw=program.bin this_file.asm",
            "",
        ]

    # 'out (c),0' (undocumented) gets a warning from sjasmplus, that it's
    # 'out (c),255' on some Z80s, unless that warning is turned off. (These
    # match a line with the instruction, and an 'org' line.)
    _OUT_C_0 = re.compile(r"^\s+out\s+\(c\),\s*0\b", re.IGNORECASE)
    _ORG = re.compile(r"^\s+org\b", re.IGNORECASE)

    def tidy_output(self, lines):
        """The lines, with 'OPT -Wno-out0' before the first 'org' if the
        output uses 'out (c),0'."""
        # Turn off the warning for 'out (c),0', if it's used (before the
        # first 'org')
        if not any(self._OUT_C_0.match(line) for line in lines):
            return lines
        for i, line in enumerate(lines):
            if self._ORG.match(line):
                return lines[:i] + [self.comment_prefix() + " (No warning that 'out (c),0' is 'out (c),255' on some Z80s)",
                                    utils.make_indent(1) + utils.force_case("OPT") + " -Wno-out0"] + lines[i:]
        return lines

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: 'ORG $2000', after 'DS' to pad a gap before a later
        range."""
        # (A second 'org' doesn't pad the binary, so a gap after the code
        # before needs padding)
        result = [""]
        if not first:
            result.append("%s%s %s - $" % (utils.make_indent(1), utils.force_case("DS"), self.hex4(start_addr)))
        return result + ["%s%s %s" % (utils.make_indent(1), utils.force_case("ORG"), self.hex4(start_addr)), ""]

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: sjasmplus's DISP, which assembles the code that
        follows for the given address."""
        return [utils.make_indent(1) + utils.force_case("DISP") + " " + self.hex(dest)]

    def pseudopc_end(self, dest, source, length, move_id):
        """'ENT', ending the DISP block."""
        return [utils.make_indent(1) + utils.force_case("ENT"), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly: sjasmplus's
        ASSERT stops with 'Assertion failed' if its expression is false."""
        result = []
        if config.get_include_assertions():
            spa = sorted((str(expr), self.assertion_value(value)) for expr, value in self.pending_assertions.items())
            old = None
            for expr, value in spa:
                # (The same expression can be used at more than one address)
                if old != (expr, value):
                    result.append("%s%s (%s) == %s" % (utils.make_indent(1), utils.force_case("ASSERT"), expr, value))
                old = (expr, value)
        return result

    def char_literal(self, n):
        """A printable character in single quotes, or "'" for a single
        quote."""
        # Single quotes have no escapes in sjasmplus: a backslash is '\', and
        # a single quote is written in double quotes, "'"
        if n == ord("'"):
            return '"\'"'
        if utils.isprint(n):
            return "'" + chr(n) + "'"
        return None

    def picture_binary(self, s):
        """The binary digits as they are."""
        # sjasmplus has no picture binary (e.g. z88dk-z80asm's '%"--##"'),
        # so it's the binary digits
        return s

    def include_binary_file(self, binary_filepath):
        """'INCBIN "file"'."""
        return utils.make_indent(1) + utils.force_case("INCBIN") + ' "' + binary_filepath + '"'
