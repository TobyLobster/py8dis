"""
ca65 assembler (from cc65)
"""

import config
import session
import utils
import assembler
import cpu6510
import textencoding

# ca65's names for the undocumented opcodes whose names differ from py8dis's
# (see Cpu6510)
_UNDOCUMENTED_MNEMONICS = {"LXA": "LAX", "SBX": "AXS"}

# The names ca65 doesn't accept as labels, besides the CPU's mnemonics: the
# registers, and 'z' (the zero page prefix, 'z:')
_RESERVED_NAMES = {"a", "x", "y", "z"}

# The mnemonics of each CPU (lower case), which ca65 doesn't accept as labels
_MNEMONICS_6502 = set("""
    adc and asl bcc bcs beq bit bmi bne bpl brk bvc bvs clc cld cli clv cmp cpx cpy dec dex dey eor inc inx iny
    jmp jsr lda ldx ldy lsr nop ora pha php pla plp rol ror rti rts sbc sec sed sei sta stx sty tax tay tsx txa txs tya""".split())
_MNEMONICS_65C02 = _MNEMONICS_6502 | set("bra phx phy plx ply stz trb tsb".split())
_MNEMONICS_6502X = _MNEMONICS_6502 | set("alr anc ane arr axs dcp isc jam las lax rla rra sax sha shx shy slo sre tas".split())

# The linker configuration for a plain binary (see disassembly_start())
LINKER_CONFIG = [
    "MEMORY { MAIN: start = $0000, size = $10000, file = %O; }",
    "SEGMENTS { CODE: load = MAIN, type = rw; }",
]

class Ca65(assembler.Assembler):
    """This class encapsulates ca65-specific syntax and features. (Tested
    with ca65 and ld65 V2.18, as in Ubuntu's cc65 2.19-1. ca65 makes an
    object file, which its linker, ld65, makes into a binary with a
    configuration file: see disassembly_start().)"""

    def __init__(self):
        super().__init__()

    def get_name(self):
        return "ca65"

    def cpus_supported(self):
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """format a two digit hex number"""
        return "${0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """format a four digit hex number"""
        # (ca65 chooses zero page or absolute addressing from an operand's
        # value, not how it's written, so '$0012' is zero page, if it's
        # defined before it's used)
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
                'MOD': '.mod',
                  '%': '.mod',
                 '==': '=',
                 '!=': '<>',
        }

    def binary_precedence(self):
        # Measured by assembling test expressions with ca65 V2.18: unlike C,
        # the bitwise operators are at the arithmetic levels (e.g. '6&3+1' is
        # 3, '1+2<<1' is 5, '1|2*3' is 7)
        return { '*': 7, 'DIV': 7, 'MOD': 7, 'AND': 7, 'EOR': 7, '<<': 7, '>>': 7,
                 '+': 6, '-': 6, 'OR': 6,
        }

    def unary_precedence(self):
        # '<' and '>' (low and high byte) bind more tightly than any binary
        # operator, so '>ab+1' is '(>ab)+1', as in beebasm
        return { '<': 90, '>': 90, 'NOT': 90 }

    def unary_operators(self):
        """Returns a dictionary that translates generic unary operator names
        into the assembler specific versions"""
        # 'generic name: assembler specific name'
        return { 'NOT': '~',
                   '!': '~',
        }

    def _reserved(self):
        if config.get_cmos():
            return _RESERVED_NAMES | _MNEMONICS_65C02
        if getattr(session.current().cpu, "has_undocumented_opcodes", False):
            return _RESERVED_NAMES | _MNEMONICS_6502X
        return _RESERVED_NAMES | _MNEMONICS_6502

    def _check_name(self, name):
        # ca65 doesn't accept a register's name, 'z' or a mnemonic as a label
        name = str(name)
        if name.lower() in self._reserved():
            what = "a register's name" if name.lower() in ("a", "x", "y") else ("the zero page prefix ('z:')" if name.lower() == "z" else "an instruction's mnemonic")
            utils.die("ca65 doesn't accept '{0}' as a label, since it's {1}: rename it".format(name, what))

    def inline_label(self, name):
        """Returns the string for defining a label in the first column."""
        self._check_name(name)
        return "%s:" % name

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
        """Preamble to be output at the start of the disassembly: how to
        assemble it (with a linker configuration that makes a plain binary,
        since ca65 needs its linker), and the CPU."""
        c = self.comment_prefix()
        result = [
            c + " Assemble with ca65 and its linker (from cc65), to a plain binary:",
            c + "     cl65 -t none -C ca65.cfg -o program.bin this_file.asm",
            c + " where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:",
        ] + [c + "     " + line for line in LINKER_CONFIG] + [
            c + " ('-t none': cl65's default target is the C64, whose character map would change",
            c + " the strings.)",
            "",
        ]
        # (The CPU's name is a string, so it's always lower case)
        if config.get_cmos():
            result += [utils.make_indent(1) + utils.force_case(".setcpu") + ' "65C02"', ""]
        elif getattr(session.current().cpu, "has_undocumented_opcodes", False):
            result += [utils.make_indent(1) + utils.force_case(".setcpu") + ' "6502X"', ""]
        return result + self._charmap_lines()

    # Text encodings. ca65's character map ('.charmap', from a character in
    # the source to a byte) applies to every string and character literal,
    # and can't be switched for one string and back (V2.18 has no
    # '.pushcharmap'), so it's for the session's encoding, as acme's '!ct':
    # if that isn't ASCII, strings and character literals in it are written
    # as text, and the output starts with the character map for it, if it
    # has any. Strings in other encodings, including ASCII, are written as
    # bytes, with their text in a comment.

    def _main_encoding(self):
        """The session's encoding, which the character map is for"""
        return textencoding.current()

    def _charmap_lines(self):
        """The '.charmap' lines for the session's encoding, if it isn't ASCII
        and the output has strings or character literals in it: each
        character whose byte isn't its ASCII code (e.g. '.charmap $61, $41'
        for PETSCII's 'a')"""
        import classification
        import mainformatter
        main = self._main_encoding()
        if main.name == "ascii":
            return []
        used = any(isinstance(c, classification.String) and c.encoding.name == main.name for c in session.current().classifications.classifications)
        used = used or any(formatter is mainformatter.char_formatter for formatter in session.current().disassembly.format_hint.values())
        if not used:
            return []
        c = self.comment_prefix()
        result = [c + " The character map for " + {"petscii": "PETSCII", "screen": "screen codes"}[main.name] +
                  " (for strings and character literals)"]
        for byte, char in sorted(main.chars.items(), key=lambda item: ord(item[1])):
            if ord(char) != byte:
                result.append("%s%s %s, %s %s '%s'" % (utils.make_indent(1), utils.force_case(".charmap"), self.hex2(ord(char)), self.hex2(byte), c, char))
        return result + [""]

    def text_directive(self, encoding):
        # (See above)
        if encoding.name == self._main_encoding().name:
            return utils.force_case(".byte ")
        return None

    def text_chr(self, n, encoding):
        if encoding.name == "ascii":
            return self.string_chr(n)
        c = encoding.char(n)
        return None if c == '"' else c

    def encoded_char_literal(self, n, encoding):
        # Only in the session's encoding (see above)
        if encoding.name != self._main_encoding().name:
            return None
        if encoding.name == "ascii":
            return self.char_literal(n)
        c = encoding.char(n)
        return None if c is None else "'" + c + "'"

    def code_start(self, start_addr, end_addr, first):
        """At the start of the code we provide the address at which to
        assemble."""
        # ('.org' sets the address, but the bytes still follow on in the
        # output, so a gap after the code before needs padding)
        result = [""]
        if not first:
            result.append("%s%s %s - *" % (utils.make_indent(1), utils.force_case(".res"), self.hex4(start_addr)))
        return result + ["%s%s %s" % (utils.make_indent(1), utils.force_case(".org"), self.hex4(start_addr)), ""]

    def code_end(self):
        return []

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute."""
        # (The bytes follow on in the output, so '.org' does this)
        return [utils.make_indent(1) + utils.force_case(".org %s" % self.hex4(dest))]

    def pseudopc_end(self, dest, source, length, move_id):
        return [utils.make_indent(1) + utils.force_case(".org %s" % self.hex4(source + length)), ""]

    def disassembly_end(self):
        """Output assertions at the end of the disassembly"""
        result = []

        # ca65's '.assert condition, error, "message"' stops with the message
        # if the condition isn't true (the message can't contain '"')
        if config.get_include_assertions():
            spa = sorted((str(expr), self.hex(value) if type(value) == int else '"' + value + '"') for expr, value in self.pending_assertions.items())
            old = ("", 0)
            for expr, value in spa:
                if old != (expr, value):
                    message = ("Assertion failed: %s = %s" % (expr, value)).replace('"', "'")
                    result.append('%s (%s) = %s, %s, "%s"' % (utils.force_case(".assert"), expr, value, utils.force_case("error"), message))
                old = (expr, value)

        return result

    def undocumented_6502_opcodes(self):
        # With '.setcpu "6502X"' ca65 assembles the undocumented mnemonics,
        # but where an instruction has several opcodes it uses only one, the
        # same as acme and 64tass (found by assembling each with ca65 V2.18),
        # so the others are written as data.
        return cpu6510.ASSEMBLED_UNDOCUMENTED_OPCODES

    def undocumented_6502_mnemonic(self, mnemonic):
        # ca65 calls LXA 'lax #imm', and SBX 'axs'
        return _UNDOCUMENTED_MNEMONICS.get(mnemonic, mnemonic)

    def wrapped_branch_operand(self, label, offset):
        # ca65 doesn't wrap a branch's target round the top or bottom of
        # memory, so give it relative to the branch ('*' is its address)
        return "*{0:+d}".format(offset)

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero
        # page address. e.g. 'lda a:addr,x'
        return "%s%s %s%s%s%s" % (utils.make_indent(1), instruction, prefix, utils.force_case("a:"), operand, suffix)

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return "<"

    def direct_operand(self, operand):
        # ca65 takes an operand starting with a bracket to be indirect, so
        # 'lda (table+1) - 1,y' is an error
        return "0+" + operand

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case(".byte ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case(".word ")

    def string_prefix(self):
        # For outputting strings
        return utils.force_case(".byte ")

    def char_literal(self, n):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible (only if the session's
        # encoding is ASCII, see above)
        if self._main_encoding().name != "ascii":
            return None
        if utils.isprint(n):
            return "'" + chr(n) + "'"
        return None

    def string_chr(self, n):
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible. (A '"' can't be written in
        # a string; a backslash is an ordinary character.)
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
        # data. ca65 doesn't support this.
        return s

    def sanitise_line(self, s):
        return s

    def supports_signed_integers(self):
        # '.byte -1' is a range error, so don't use signed integers
        return False

    def include_binary_file(self, binary_filepath):
        return utils.make_indent(1) + utils.force_case(".incbin") + ' "' + binary_filepath + '"'
