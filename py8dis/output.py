"""
Output

The disassembly is described by a list of line objects, which say what to
output rather than holding text: an instruction (its mnemonic and operand), a
block of data bytes or words, a string, a blank line. render_lines() turns
them into text for the current assembler.

(This is being introduced in steps: see "Structure the output before
rendering" in claude/architecture-notes-2026-10-21.md in the project. For now,
each classification's lines are rendered as soon as they are made, in the
same order as before, since rendering is still where label names are chosen.)
"""

import classification
import config
import mainformatter
import memorymanager
import movemanager
import session
import utils


class Line:
    """A line (or several lines) of output."""

    def render(self):
        """The text for the current assembler, as a list of lines (each a
        string or a LazyString)."""
        raise NotImplementedError


class Blank(Line):
    """A blank line."""

    def render(self):
        return [""]


class Instruction(Line):
    """A CPU instruction, e.g. 'lda #3' or 'jsr oswrch'.

    'mnemonic' is the mnemonic (before upper or lower casing, and including
    e.g. ' A' for an explicit accumulator operand).

    'operand' is the operand (an expression, label or string), or None for
    none, written as prefix + operand + suffix, e.g. '(' + 'ptr' + '),y'.
    (The suffix is upper or lower cased, but the prefix isn't.)

    'form' says how the instruction is written:
        PLAIN          mnemonic, then the operand (if any)
        FORCE_ABSOLUTE absolute addressing must be forced, since the operand
                       is a zero page address (the assembler says how)
        AS_DATA        the assembler can't force absolute addressing, so the
                       instruction is written as data bytes, with the
                       instruction in a comment

    'char_literal' is a character to show in a comment after the instruction
    (e.g. for 'lda #65', "'A'"), or None.

    The rest place the instruction in the output: its binary location and
    length (for the hex dump), its extra indent level, a description of its
    cycle count, and the annotations (for inline comments). Without a binary
    location only text() is available."""

    PLAIN          = "plain"
    FORCE_ABSOLUTE = "force absolute"
    AS_DATA        = "as data"

    def __init__(self, mnemonic, operand=None, prefix="", suffix="", form=PLAIN, char_literal=None,
                 data_byte=None, listing_operand=None,
                 binary_loc=None, length=None, indent_level=0, cycles_description="", annotations=None):
        self.mnemonic = mnemonic
        self.operand = operand
        self.prefix = prefix
        self.suffix = suffix
        self.form = form
        self.char_literal = char_literal

        # For AS_DATA: the first byte (the opcode, as a constant), and the
        # operand for the instruction shown in the comment
        self.data_byte = data_byte
        self.listing_operand = listing_operand

        self.binary_loc = binary_loc
        self.length = length
        self.indent_level = indent_level
        self.cycles_description = cycles_description
        self.annotations = annotations

    def placed(self, binary_loc, length, indent_level, cycles_description, annotations):
        """Set where the instruction is in the output (see the class docs)."""
        self.binary_loc = binary_loc
        self.length = length
        self.indent_level = indent_level
        self.cycles_description = cycles_description
        self.annotations = annotations
        return self

    def text(self):
        """The text of the instruction (indented, but without its extra
        indent level or any inline comment), as a LazyString since its
        labels may not be named yet."""

        mnemonic = utils.force_case(self.mnemonic)
        suffix = utils.force_case(self.suffix)
        assembler = config.get_assembler()

        if self.operand is None:
            return "%s%s" % (utils.make_indent(1), mnemonic)

        if self.form == Instruction.FORCE_ABSOLUTE:
            return assembler.force_abs_instruction(mnemonic, self.prefix, self.operand, suffix)

        if self.form == Instruction.AS_DATA:
            # (The comment includes an acme-style '+2' suffix to help show
            # what's going on.)
            listing = utils.LazyString("%s%s%s", self.prefix, self.listing_operand, suffix)
            return utils.LazyString("%s%s%s, <(%s), >(%s) ; %s+2 %s", utils.make_indent(1), assembler.byte_prefix(),
                                    self.data_byte, self.operand, self.operand, mnemonic, listing)

        result = utils.LazyString("%s%s %s%s%s", utils.make_indent(1), mnemonic, self.prefix, self.operand, suffix)
        if self.char_literal is not None:
            result = result + " %s %s" % (assembler.comment_prefix(), self.char_literal)
        return result

    def render(self):
        line = utils.LazyString(utils.make_indent(self.indent_level) + "%s", self.text())
        return [mainformatter.add_inline_comment_including_hexdump(self.binary_loc, self.length, self.cycles_description, self.annotations, line)]


class DataBlock(Line):
    """A block of data bytes or words, laid out as a table (e.g. several
    '!byte' lines, each with some number of values).

    'element_size' is 1 for bytes or 2 for words; 'length' is in bytes.
    'cols' is the number of values per line, or None to fit as many as
    possible."""

    def __init__(self, binary_loc, length, cols, element_size, annotations):
        assert isinstance(binary_loc.binary_addr, memorymanager.BinaryAddr)
        assert memorymanager.is_valid_binary_addr(binary_loc.binary_addr)
        assert length >= 1
        assert element_size in (1, 2)
        assert length % element_size == 0
        self.binary_loc = binary_loc
        self.length = length
        self.cols = cols
        self.element_size = element_size
        self.annotations = annotations

    def items(self):
        """The values (expressions, labels or formatted numbers)."""
        binary_addr = self.binary_loc.binary_addr
        if self.element_size == 1:
            return list(classification.get_constant8(binary_addr + i) for i in range(self.length))
        return list(classification.get_constant16(binary_addr + i) for i in range(0, self.length, 2))

    def render(self):
        # TODO: We should also support "just emit with no padding or
        # attempt to align columns but not spilling past data_width
        # unless a single item forces it", a pseudo "word wrapping"
        # style
        data = self.items()
        assembler = config.get_assembler()
        data_prefix = assembler.byte_prefix() if self.element_size == 1 else assembler.word_prefix()

        prefix = utils.make_indent(1) + data_prefix         # (e.g. prefix="    !byte" for example)
        data_width = config.get_inline_comment_column() - len(prefix) - 1

        def format_line(text, start_index, end_index):
            line_binary_loc = movemanager.BinaryLocation(self.binary_loc.binary_addr + start_index*self.element_size, self.binary_loc.move_id)
            return mainformatter.add_inline_comment_including_hexdump(line_binary_loc, (end_index - start_index)*self.element_size, "", self.annotations, prefix + text)

        return utils.format_strings_in_a_table(data, data_width, self.cols, format_line)


class StringData(Line):
    """A string of data bytes (e.g. '.asc "Hello", 13'), split over several
    lines if it's too long for one.

    If there's an expression for its first byte (given by expr()), the
    expression is output instead of the bytes."""

    def __init__(self, binary_loc, length, annotations):
        self.binary_loc = binary_loc
        self.length = length
        self.annotations = annotations

    def render(self):
        expressions = session.current().classifications.expressions
        memory_binary = session.current().memory.binary
        assembler = config.get_assembler()
        binary_loc = self.binary_loc
        annotations = self.annotations

        result = []
        prefix = utils.make_indent(1) + assembler.string_prefix()
        s = prefix
        state = 0       # 0=not started first string yet, 1=within string, 2=finished string
        start_line_i = 0

        if binary_loc.binary_addr in expressions:
            s = classification.get_expression(binary_loc.binary_addr, memory_binary[binary_loc.binary_addr])
            result.append(mainformatter.add_inline_comment_including_hexdump(binary_loc, self.length, "", annotations, prefix + s))
            return result

        i = 0
        while(i < self.length):
            c = memorymanager.get_u8_binary(binary_loc.binary_addr + i)
            c_in_string = assembler.string_chr(c)

            # Calculate how to add 'c' to  the current assembly string in 'next_char'
            next_char = ""
            next_state = state
            if c_in_string is not None:
                if state == 0:
                    next_char += '"'
                elif state == 2:
                    next_char += ', "'
                next_state = 1
                next_char += c_in_string
            else:
                if state == 1:
                    next_char += '", '
                elif state == 2:
                    next_char += ", "
                next_state = 2
                if c == ord('"'):
                    next_char += "'\"'"
                else:
                    next_char += classification.get_constant8(binary_loc.binary_addr + i)

            new_s = s + next_char
            len_new_s = len(new_s)
            if next_state == 1:
                len_new_s += 1

            if len_new_s > (config.get_inline_comment_column() - 1):
                # Save out the line before the next char
                if state == 1:
                    s += '"'
                temp_binary_loc = movemanager.BinaryLocation(binary_loc.binary_addr + start_line_i, binary_loc.move_id)
                result.append(mainformatter.add_inline_comment_including_hexdump(temp_binary_loc, i - start_line_i, "", annotations, s))
                s = prefix
                start_line_i = i
                state = 0
            else:
                s = new_s
                state = next_state
                i += 1

        if s != prefix:
            if state == 1:
                s += '"'
            temp_binary_loc = movemanager.BinaryLocation(binary_loc.binary_addr + start_line_i, binary_loc.move_id)
            result.append(mainformatter.add_inline_comment_including_hexdump(temp_binary_loc, self.length - start_line_i, "", annotations, s))
        return result


def render_lines(lines):
    """The text for a list of line objects, as a list of lines."""
    result = []
    for line in lines:
        result.extend(line.render())
    return result
