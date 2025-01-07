"""
Beebasm assembler
"""

from __future__ import print_function
import sys

import assembler
import config
import disassembly
import mainformatter
import memorymanager
import movemanager
import utils

class Beebasm(assembler.Assembler):
    """This class encapsulates beebasm-specific syntax and features."""

    def __init__(self):
        super(assembler.Assembler, self).__init__()

        self.explicit_a = True          # e.g. Output 'ROR A', not just 'ROR'

    def get_name(self):
        return "beebasm"

    def cpus_supported(self):
        return ["6502", "65c02"]

    def hex2(self, n):
        return "&%s" % utils.plainhex2(n)

    def hex4(self, n):
        return "&%s" % utils.plainhex4(n)

    def hex(self, n):
        if n <= 0xff:
            return self.hex2(n)
        else:
            return self.hex4(n)

    def inline_label(self, name):
        return ".%s" % name

    def explicit_label(self, name, value, offset=None, align=0):
        # Output when declaring a label with an explicit value:
        #
        #   i.e. 'label = value'
        #
        # with an optional offset added to the value, and optional column
        # alignment at the equals sign.
        return "%s= %s%s" % (utils.tab_to(name + " ", align), value, "" if offset is None else "+%d" % offset)

    def comment_prefix(self):
        return ";"

    def disassembly_start(self):
        # Preamble to be output at the start of the disassembly.
        if config.get_cmos():
            return [utils.make_indent(1) + utils.force_case("cpu 1"), ""]
        return []

    def code_start(self, start_addr, end_addr, first):
        # At the start of the code we provide the address at which to assemble.
        result = ["", utils.make_indent(1) + utils.force_case("org %s" % self.hex4(start_addr))]
        result.append("")
        return result

    def code_end(self):
        return []

    def format_comment(self, s, indent=1):
        text = mainformatter.format_comment(s, indent)
        return "\n".join("%s%s %s" % (config.get_indent_string() * indent, config.get_assembler().comment_prefix(), line) for line in text.split("\n"))

    def find_temporary_area(self, dest, source, length):
        pydis_start, pydis_end = memorymanager.get_entire_load_range()

        temp_start = -1
        overlap_length = -1
        overlap_start = -1
        if dest < source:
            if dest + length > pydis_start:
                # What area is overlapping?
                overlap_start  = max(dest, pydis_start)
                overlap_length = source - overlap_start

                # Find an area of the memory map that is not used by the binary file. Try the high end of memory first
                temp_start = 0xffff - overlap_length
                if temp_start < (source + length):
                    # not enough room high in memory, so try low instead
                    temp_start = 0
                    assert (temp_start + length) <= pydis_start, "Not enough memory to assemble in beebasm!"

            area_to_clear_start = dest
            area_to_clear_end   = min(dest + length, source)
        else:
            area_to_clear_start = max(dest, source + length)
            area_to_clear_end   = dest + length

        return temp_start, overlap_start, overlap_length, area_to_clear_start, area_to_clear_end

    def pseudopc_start(self, dest, source, length):
        # Used when assembling code at a different address to where it will
        # actually execute.

        result = [""]

        # Find a temporary memory range we can use to move existing code out of the way (if needed)
        temp_start, overlap_start, overlap_length, area_to_clear_start, area_to_clear_end = self.find_temporary_area(dest, source, length)
        if overlap_length > 0:
            result.append(self.format_comment("1. We want to move to a lower memory address to assemble the next block of code at it's runtime address. First we temporarily copy the existing code/data that overlaps out of the way while we do so.\n(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))
            result.append(utils.make_indent(1) + utils.force_case("copyblock %s, %s, %s" % (self.hex(overlap_start), self.hex(overlap_start + overlap_length), self.hex(temp_start))))

            result.append("")
            result.append(self.format_comment("2. Clear the existing code area so that we are allowed to assemble there again."))
            result.append(utils.make_indent(1) + utils.force_case("clear %s, %s" % (self.hex(overlap_start), self.hex(overlap_start + overlap_length))))

            result.append("")
            result.append(self.format_comment("3. Assemble the new block at it's runtime address."))

        move_id = movemanager.move_id_for_binary_addr[source]
        result.append(utils.make_indent(1) + utils.force_case("org %s" % self.hex(dest)))
        # TODO: We will need some labels in pseudopc_end() but by then
        # it will be too late to create them, so do it now. Is this
        # hacky or OK?
        #
        # TODO: The idea of including move_id here is to force the
        # labels to be emitted "around" the pseudopc-emulation block,
        # which is both more readable and necessary in some cases to
        # avoid assembly problems where a label is not forward
        # declared. It isn't working quite right yet.
        disassembly.get_label(dest, source, move_id)
        disassembly.get_label(dest + length, source, move_id)
        disassembly.get_label(source, source, move_id)
        return result

    # TODO: General comment - I've currently given up on generating
    # "guard" for beebasm, I can probably do this later but on a "whole
    # program" basis - note that guard sets m_aFlags[x], it is not a
    # "guard=x" and there's only one such guard active at a time, so we
    # need to set it at the end of distinct non-adjoining ranges (I
    # think)
    def pseudopc_end(self, dest, source, length):
        assert isinstance(dest, memorymanager.RuntimeAddr)
        assert isinstance(source, memorymanager.BinaryAddr)

        result = [""]
        # TODO: Use LazyString?
        move_id = movemanager.move_id_for_binary_addr[source]

        # Find a temporary memory range we can use to move existing code out of the way (if needed)
        temp_start, overlap_start, overlap_length, area_to_clear_start, area_to_clear_end = self.find_temporary_area(dest, source, length)
        if overlap_length > 0:
            comment_prefix = "4. "
        else:
            comment_prefix = ""
        result.append(self.format_comment(comment_prefix + "Copy the newly assembled block of code back to it's proper place in the binary file.\n(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))

        # Output COPYBLOCK command
        result.append("%s%s %s, %s, %s" % (utils.make_indent(1),
            utils.force_case("copyblock"),
            disassembly.get_label(dest,          source, move_id),
            disassembly.get_label(dest + length, source, move_id),
            disassembly.get_label(source,        source, move_id)))

        # Output CLEAR command
        result.append("")
        result.append(self.format_comment(comment_prefix + "Clear the area of memory we just temporarily used to assemble the new block, allowing us to assemble there again if needed"))
        result.append("%s%s %s, %s" % (utils.make_indent(1),
            utils.force_case("clear"),
            self.hex(area_to_clear_start),
            self.hex(area_to_clear_end)))

        if overlap_length > 0:
            # Output COPYBLOCK command
            result.append("")
            result.append(self.format_comment("5. Copy the previous existing code back to it's proper place in the binary file.\n(Note the parameter order: 'copyblock <start>,<end>,<dest>')"))
            result.append("%s%s %s, %s, %s" % (utils.make_indent(1),
                utils.force_case("copyblock"),
                self.hex(temp_start),
                self.hex(temp_start + overlap_length),
                disassembly.get_label(overlap_start, source, move_id)))
            result.append("")
            result.append(self.format_comment("6. Clear the temporary code area so we can assemble there in the future if needed."))
            result.append("%s%s %s, %s" % (utils.make_indent(1),
                utils.force_case("clear"),
                self.hex(temp_start),
                self.hex(temp_start + overlap_length)))

        # Output ORG command
        result.append("")
        if overlap_length > 0:
            comment_prefix = "7. "
        else:
            comment_prefix = ""
        result.append(self.format_comment(comment_prefix + "Set the program counter to the next position in the binary file."))
        result.append("%s%s %s + (%s - %s)" % (utils.make_indent(1),
            utils.force_case("org"),
            disassembly.get_label(source,        source, move_id),
            disassembly.get_label(dest + length, source, move_id),
            disassembly.get_label(dest,          source, move_id)))

        result.append("")
        return result

    def disassembly_end(self):
        result = []

        # At the end of the assembly, we output assertions.
        if config.get_include_assertions():
            spa = sorted((str(expr), self.hex(value)) for expr, value in self.pending_assertions.items())

            old = ("", 0)
            for expr, value in spa:
                if (expr != old[0]) or (value != old[1]):
                    result.append(utils.make_indent(1) + utils.force_case("assert ") + "%s == %s" % (expr, value))
                old = (expr, value)

        result.append("")
        s = utils.force_case("save")
        if self.output_filename is None:
            s += " pydis_start, pydis_end"
        else:
            s += ' "%s", pydis_start, pydis_end' % self.output_filename
        result.append(s)
        return result

    def force_abs_instruction(self, instruction, prefix, operand, suffix):
        # Ensure the instruction uses an absolute address rather than a zero page address.
        # e.g. 'lda+2 addr'
        # Sadly beebasm doesn't currently have a way to do this.
        return None

    def force_zp_label_prefix(self):
        # Prefix to take the low byte of a label
        return ""

    def byte_prefix(self):
        # For outputting bytes
        return utils.force_case("equb ")

    def word_prefix(self):
        # For outputting words
        return utils.force_case("equw ")

    def string_prefix(self):
        # For outputting strings
        return utils.force_case("equs ")

    def string_chr(self, c):
        # When composing a literal character, this returns a character string
        # from an integer, or None if not possible
        if utils.isprint(c) and chr(c) not in ('"'):
            return chr(c)
        return None

    def binary_format(self, s):
        # For outputting a value as binary
        return "%" + s

    def picture_binary(self, s):
        # Converts a string of '0' and '1's into '.' and '#'s for visualising
        # data. Sadly, beebasm does not support this.
        return s

    def sanitise(self, s):
        return s

config.set_assembler(Beebasm())
