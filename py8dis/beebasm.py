"""
Beebasm assembler

Writes the output for beebasm (https://github.com/stardot/beebasm), py8dis's
default assembler, for the 6502, the 65C02 and the 6510 (the 6502 with its
undocumented opcodes, which beebasm doesn't assemble, so they're written as
data bytes, with the instruction in a comment).

Its syntax is reminiscent of BBC BASIC's built-in assembler: '.name' defines
a label, '&' starts a hex number, 'equb', 'equw' and 'equs' are the data
directives, 'P%' is the current address, and AND, OR, EOR, DIV, MOD and
NOT(...) are words. The output starts with 'cpu 1' for the 65C02, and the
main disassembly ends with the assertions (beebasm's 'assert', which it
checks), then a 'save' command for the whole program, from pydis_start to
pydis_end (with the file name from set_output_filename(), if any).

py8dis works round a few things beebasm can't do:

- There's no way to force absolute addressing for an operand in zero page,
  so such an instruction is written as data bytes, with the instruction in
  a comment (see can_force_absolute()).

- There's no directive to assemble code for one address while placing it
  at another, so a moved block (see move()) is assembled at its runtime
  address, then copied to its binary address with 'copyblock', and the area
  it was assembled in is cleared with 'clear', so that it can be assembled
  at again. If the block's runtime addresses overlap the output before it,
  that output is copied out of the way first, then back again (see
  find_temporary_area(), pseudopc_start() and pseudopc_end()). The output
  has comments explaining each step.

- A relative branch whose target wraps round the top or bottom of memory is
  given relative to the branch, e.g. 'P%-16', since beebasm doesn't wrap it.

baron.py's Baron class is derived from this one.
"""

import re

import assembler
import config
import expression
import disassembly
import mainformatter
import memorymanager
import movemanager
import session
import utils
from binaryaddrtype import BinaryAddrType

class Beebasm(assembler.Assembler):
    """This class encapsulates beebasm-specific syntax and features. (See
    assembler.Assembler for what each method is for.)"""

    def __init__(self):
        super().__init__()

        self.explicit_a = True          # e.g. Output 'ROR A', not just 'ROR'

    def get_name(self):
        """'beebasm'."""
        return "beebasm"

    def cpus_supported(self):
        """The 6502, 65C02 and 6510 (whose undocumented opcodes are written
        as data)."""
        return ["6502", "65c02", "6510"]

    def hex2(self, n):
        """A byte in hex, e.g. &1f."""
        return "&{0}".format(utils.plainhex2(n))

    def hex4(self, n):
        """A four digit hex number, e.g. &001f."""
        return "&{0}".format(utils.plainhex4(n))

    def hex(self, n):
        """A hex number, with two digits up to &ff (e.g. &1f), otherwise
        four."""
        if n <= 0xff:
            return self.hex2(n)
        else:
            return self.hex4(n)

    def binary_operators(self):
        """The operators that are words in beebasm: OR, AND, EOR, DIV and
        MOD."""
        # 'generic name: assembler specific name'
        return { 'OR': 'OR',
                  '|': 'OR',
                'AND': 'AND',
                  '&': 'AND',
                'EOR': 'EOR',
                'XOR': 'EOR',
                  '^': 'EOR',
                'DIV': 'DIV',
                  '/': 'DIV',
                'MOD': 'MOD',
                  '%': 'MOD',
                 '!=': '!=',
        }

    def binary_precedence(self):
        """beebasm's precedence, including '==' (for the assertions)."""
        # Measured by assembling test expressions with beebasm. (Note that the
        # shifts bind as tightly as '*'.)
        return { '*': 6, 'DIV': 6, 'MOD': 6, '<<': 6, '>>': 6,
                 '+': 5, '-': 5,
                 '==': 4,
                 'AND': 3,
                 'OR': 2, 'EOR': 2,
        }

    def unary_precedence(self):
        """'<' and '>' bind more tightly than any binary operator."""
        # '<' and '>' (low and high byte) bind more tightly than any binary
        # operator, so '<x + 1' is '(<x) + 1'. (NOT is 'NOT(...)', see below.)
        return { '<': 90, '>': 90 }

    def expression_in_context(self, expr, text, level, context):
        """In an assertion, brackets round an expression that binds no more
        tightly than '=='; otherwise the text as it is."""
        if context == expression.ASSERTION:
            # An assertion is 'assert value == expr', so the expression needs
            # brackets if it binds no more tightly than '==' (e.g. AND).
            if level is None:
                # (The structure isn't known, e.g. an expression string from
                # the user, so look for operators that bind less tightly.)
                if re.search(r"\b(AND|OR|EOR)\b", text, re.IGNORECASE):
                    return "(%s)" % text
            elif level <= self.binary_precedence()['==']:
                return "(%s)" % text
        return text

    def unary_operators(self):
        """NOT is 'NOT(...)'. ('<' and '>' are as they are.)"""
        # 'generic name: assembler specific name'
        return { 'NOT': 'NOT(%s)',      # beebasm needs the brackets, 'NOTx' or 'NOT x' is an error
                   '!': 'NOT(%s)',
        }

    def inline_label(self, name):
        """Returns the string for defining a label in the first column:
        '.name'."""
        return ".{0}".format(name)

    def explicit_label(self, name, value, offset=None, align_column=0):
        """Output when declaring a label with an explicit value:

           i.e. 'label = value'

        with an optional offset (e.g. '+1') added to the value, with optional
        column alignment at the equals sign."""
        return "%s= %s%s" % (utils.tab_to(name + " ", align_column), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        """';'."""
        return ";"

    def disassembly_start(self):
        """Preamble to be output at the start of the disassembly: 'cpu 1',
        which selects the 65C02's instructions, for the 65C02."""
        if config.get_cmos():
            return [utils.make_indent(1) + utils.force_case("cpu 1"), ""]
        return []

    def code_start(self, start_addr, end_addr, first, previous_end=None):
        """At the start of the code we provide the address at which to
        assemble: 'org &2000'. (Nothing fills the gap before a later range:
        'save' saves the zeroes in it.)"""
        result = ["", utils.make_indent(1) + "{0} {1}".format(utils.force_case("org"), self.hex4(start_addr))]
        result.append("")
        return result

    def format_comment(self, s, indent=1):
        """A word wrapped comment (see mainformatter.format_comment()), for
        the comments explaining the steps of a move."""
        return mainformatter.format_comment(s, indent)

    def find_temporary_area(self, dest, source, length):
        """How to assemble the moved block of 'length' bytes at binary
        address 'source' and runtime address 'dest' (see pseudopc_start()):
        (temp_start, overlap_start, overlap_length, area_to_clear_start,
        area_to_clear_end).

        The block is assembled at its runtime address, then copied to its
        binary address. If it runs lower in memory than it's stored, and its
        runtime addresses overlap the output before it (which starts at
        pydis_start), the output from overlap_start up to the end of the
        block's runtime addresses, or its binary address if that's lower
        (overlap_length bytes), is in the way, so it's copied to a temporary
        area at temp_start first, and back afterwards. Otherwise those three
        are -1.

        The area from area_to_clear_start up to area_to_clear_end is the
        part of the block's runtime addresses that its copy at its binary
        address doesn't cover. It's cleared after the copy, so that it can
        be assembled at again.

        Stops with utils.die() if there isn't room in memory for the
        temporary area."""
        pydis_start, pydis_end = memorymanager.get_entire_load_range()
        header = memorymanager.file_header()
        if header is not None:
            # The output starts with a PRG file's header, or another file's
            # (see prg_header() and loaded_file_header())
            pydis_start -= header.length

        temp_start = -1
        overlap_length = -1
        overlap_start = -1
        if dest < source:
            if dest + length > pydis_start:
                # What area is overlapping? (The output the block is
                # assembled over: not the output after the block's runtime
                # addresses, which it doesn't touch)
                overlap_start  = max(dest, pydis_start)
                overlap_length = min(dest + length, source) - overlap_start

                # Find an area of the memory map to temporarily hold the overlapping
                # code/data. It mustn't overlap the binary assembled so far, or the
                # destination. Try the high end of memory first.
                #
                # (The area ends at &ffff rather than &10000 because it is copied
                # back with 'copyblock <start>, <end>, <dest>', and beebasm only
                # accepts an end address up to &ffff.)
                temp_start = 0xffff - overlap_length
                if temp_start < (source + length):
                    # not enough room high in memory, so try low instead (below
                    # both the binary and the destination)
                    temp_start = 0
                    if temp_start + overlap_length > min(dest, pydis_start):
                        utils.die("move({0}, {1}, {2}): there isn't enough free memory for beebasm to temporarily hold the {3} bytes of existing code/data the move's destination overlaps. Use acme or xa instead.".format(
                            self.hex(dest), self.hex(source), length, overlap_length))

            # (The part of the runtime area below the binary address)
            area_to_clear_start = dest
            area_to_clear_end   = min(dest + length, source)
        else:
            # (The part of the runtime area above the block's binary
            # addresses)
            area_to_clear_start = max(dest, source + length)
            area_to_clear_end   = dest + length

        return int(temp_start), int(overlap_start), int(overlap_length), int(area_to_clear_start), int(area_to_clear_end)

    def pseudopc_start(self, dest, source, length, move_id):
        """Used when assembling code at a different address to where it will
        actually execute: 'org' with the runtime address, so that the block
        is assembled there, after copying any output in the way somewhere
        else and clearing it (steps 1 to 3 in the comments it writes, see
        find_temporary_area()). pseudopc_end() copies the block to its
        binary address."""

        result = []

        # Find a temporary memory range we can use to move existing code out of the way (if needed)
        temp_start, overlap_start, overlap_length, area_to_clear_start, area_to_clear_end = self.find_temporary_area(dest, source, length)
        if overlap_length > 0:
            result.append(self.format_comment("1. We want to move to a lower memory address to assemble the next block of code at its runtime address. First we temporarily copy the existing code/data that overlaps out of the way while we do so."))
            result.append(self.format_comment("(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))
            result.append(utils.make_indent(1) + "%s %s, %s, %s" % (utils.force_case('copyblock'), disassembly.get_emitted_label(overlap_start), disassembly.get_emitted_label(overlap_start + overlap_length), disassembly.get_emitted_label(temp_start)))

            result.append("")
            result.append(self.format_comment("2. Clear the existing code area so that we are allowed to assemble there again."))
            result.append(utils.make_indent(1) + "%s %s, %s" % (utils.force_case('clear'), disassembly.get_emitted_label(overlap_start), disassembly.get_emitted_label(overlap_start + overlap_length)))

            result.append("")
            result.append(self.format_comment("3. Assemble the new block at its runtime address."))

        result.append(utils.make_indent(1) + "{0} {1}".format(utils.force_case("org"), self.hex(dest)))
        # We will need some labels in pseudopc_end() but by then
        # it will be too late to create them, so do it now.

        # (With the move ID, so that the labels are defined around the
        # block, where pseudopc_end() can use them without forward
        # references.)
        disassembly.get_label(dest, source, move_id=move_id, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
        disassembly.get_label(dest + length, source, move_id=move_id, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
        disassembly.get_label(movemanager.RuntimeAddr(int(source)), source, move_id=move_id, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
        return result

    def pseudopc_end(self, dest, source, length, move_id):
        """The end of a moved block: 'copyblock' to copy it from its runtime
        address to its binary address, 'clear' for the rest of the area it
        was assembled in, and if output was in the way, copying that back
        and clearing the temporary area (steps 4 to 7). Then 'org' sets the
        address to the binary address after the block again."""
        memory_binary = session.current().memory.binary
        assert isinstance(dest, memorymanager.RuntimeAddr)
        assert isinstance(source, memorymanager.BinaryAddr)

        result = [""]

        # Find a temporary memory range we can use to move existing code out of the way (if needed)
        temp_start, overlap_start, overlap_length, area_to_clear_start, area_to_clear_end = self.find_temporary_area(dest, source, length)
        if overlap_length > 0:
            comment_prefix = "4. "
        else:
            comment_prefix = ""
        result.append(self.format_comment(comment_prefix + "Copy the newly assembled block of code back to its proper place in the binary file."))
        result.append(self.format_comment("(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))

        # beebasm's COPYBLOCK and ORG commands can't use the address &10000. If
        # the block reaches the top of memory (at its source or destination)
        # we copy all but its last byte, and output that byte separately below.
        at_top_of_memory = (dest + length > 0xffff) or (int(source) + length > 0xffff)

        # Output COPYBLOCK command
        result.append("%s%s %s, %s, %s" % (utils.make_indent(1),
            utils.force_case("copyblock"),
            disassembly.get_emitted_label(dest),
            "*-1" if at_top_of_memory else "*",
            disassembly.get_emitted_label(int(source))))

        # Output CLEAR command
        result.append("")
        result.append(self.format_comment("Clear the area of memory we just temporarily used to assemble the new block, allowing us to assemble there again if needed"))
        result.append("%s%s %s, %s" % (utils.make_indent(1),
            utils.force_case("clear"),
            disassembly.get_emitted_label(area_to_clear_start),
            disassembly.get_emitted_label(area_to_clear_end)))

        if overlap_length > 0:
            # Output COPYBLOCK command
            result.append("")
            result.append(self.format_comment("5. Copy the previous existing code back to its proper place in the binary file."))
            result.append(self.format_comment("(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))
            result.append("%s%s %s, %s, %s" % (utils.make_indent(1),
                utils.force_case("copyblock"),
                disassembly.get_emitted_label(temp_start),
                disassembly.get_emitted_label(temp_start + overlap_length),
                disassembly.get_emitted_label(overlap_start)))
            result.append("")
            result.append(self.format_comment("6. Clear the temporary code area so we can assemble there in the future if needed."))
            result.append("%s%s %s, %s" % (utils.make_indent(1),
                utils.force_case("clear"),
                disassembly.get_emitted_label(temp_start),
                disassembly.get_emitted_label(temp_start + overlap_length)))

        # Output ORG command
        result.append("")
        if overlap_length > 0:
            comment_prefix = "7. "
        else:
            comment_prefix = ""
        result.append(self.format_comment(comment_prefix + "Set the program counter to the next position in the binary file."))
        if at_top_of_memory:
            # Output the last byte of the block directly, which also leaves the
            # program counter at the next position in the binary file.
            last_byte_binary_addr = int(source) + length - 1
            result.append("%s%s %s" % (utils.make_indent(1), utils.force_case("org"), self.hex(last_byte_binary_addr)))
            result.append("%s%s%s%s The last byte of the block (not copied above, as the block reaches the top of memory)" % (
                utils.make_indent(1),
                self.byte_prefix(),
                utils.tab_to(self.hex2(memory_binary[last_byte_binary_addr]), 8),
                self.comment_prefix()))
        else:
            result.append("%s%s %s + (* - %s)" % (utils.make_indent(1),
                utils.force_case("org"),
                disassembly.get_emitted_label(int(source)),
                disassembly.get_emitted_label(dest)))

        result.append("")
        return result

    def disassembly_end(self):
        """Output assertions at the end of the disassembly ('assert value ==
        expr', which beebasm checks), then 'save' for the whole program:
        from pydis_start (or two bytes before it, for a PRG file's header)
        to pydis_end, with the file name from set_output_filename(), if
        any."""
        result = []

        if config.get_include_assertions():
            # (Sorted by the expression's text and value)
            spa = sorted(((str(expr), self.assertion_value(value), expr) for expr, value in self.pending_assertions.items()), key=lambda x: x[:2])

            old = ("", 0)
            for expr_text, value, expr in spa:
                # (The same expression can be used at more than one address)
                if (expr_text != old[0]) or (value != old[1]):
                    result.append(utils.make_indent(1) + utils.force_case("assert ") + "%s == %s" % (value, expression.render(expr, expression.ASSERTION)))
                old = (expr_text, value)

        result.append("")
        s = utils.force_case("save")
        output_filename = session.current().output_filename
        # (Starting with the header of a PRG file, or another file's, see
        # prg_header() and loaded_file_header())
        header = memorymanager.file_header()
        start = "pydis_start - {0}".format(header.length) if header is not None else "pydis_start"
        if output_filename is None:
            s += " %s, pydis_end" % start
        else:
            s += ' "%s", %s, pydis_end' % (output_filename, start)
        result.append(s)
        return result

    def uses_current_address(self, text):
        """True if the text has 'P%' outside its strings and character
        literals."""
        # 'P%' (or '*') is the current address; py8dis only writes 'P%'. An
        # assertion with it would be checked at the end of the file, where
        # P% has another value (so beebasm would stop with an error)
        return re.search(r"P%", _without_quoted_text(text), re.IGNORECASE) is not None

    def wrapped_branch_operand(self, label, offset):
        """Relative to the branch's address, e.g. 'P%-16'."""
        # beebasm doesn't wrap a branch's target, but takes an address past
        # the top or bottom of memory, so give it relative to the branch
        return "P%{0:+d}".format(offset)

    def can_force_absolute(self):
        """False: such an instruction is written as data bytes."""
        # Sadly beebasm doesn't currently have a way to do this.
        return False

    def force_zp_label_prefix(self):
        """No prefix (an empty string)."""
        # Prefix to take the low byte of a label, used in control files
        # (e.g. dfs226.py) to make sure an instruction uses zero page addressing
        return ""

    def byte_prefix(self):
        """'equb '."""
        # For outputting bytes
        return utils.force_case("equb ")

    def word_prefix(self):
        """'equw '."""
        # For outputting words
        return utils.force_case("equw ")

    def string_prefix(self):
        """'equs '."""
        # For outputting strings
        return utils.force_case("equs ")

    def char_literal(self, n):
        """A printable character in single quotes, e.g. 'a', except a double
        quote."""
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        quote = "'"
        if utils.isprint(n) and chr(n) not in ('"'):
            return quote + chr(n) + quote
        return None

    def string_chr(self, n):
        """A printable character as it is, except a double quote (which
        output.StringData writes as '"', outside the string's quotes)."""
        # When composing a literal string, this returns a character string
        # from an integer, or None if not possible
        if utils.isprint(n) and chr(n) not in ('"'):
            return chr(n)
        return None

    def binary_format(self, s):
        """'%' then the digits, e.g. %00101100."""
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        """The binary digits as they are."""
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data. Sadly, beebasm does not support this.
        return s

    def sanitise_line(self, s):
        """The line as it is."""
        return s

    def supports_signed_integers(self):
        """True: e.g. 'equb -2'."""
        return True

    def include_binary_file(self, binary_filepath):
        """'incbin "file"'."""
        return utils.make_indent(1) + utils.force_case("incbin") + ' "' + binary_filepath + '"'

def _without_quoted_text(text):
    """The text without its strings and character literals, e.g. for 'P%'
    in an expression. (A string can have a double quote in it as two, as
    Baron allows.)"""
    return re.sub(r"\"(?:[^\"]|\"\")*\"|'[^']'", "", text)
