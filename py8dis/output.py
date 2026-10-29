"""
Output

The disassembly is described by a list of line objects, which say what to
output rather than holding text: an instruction (its mnemonic and operand), a
block of data bytes or words, a string, a blank line. render_lines() turns
them into text for the current assembler.

disassembly.emit() builds the whole output as a list of these lines. Each
line is resolved as it's made (see Line.resolve()): this makes any decisions
that depend on what's been output so far, e.g. naming labels used for the
first time (in e.g. comments), and choosing which label definitions are
output where. Then the lines are rendered.

(This is being introduced in steps: see "Structure the output before
rendering" in claude/architecture-notes-2026-10-21.md in the project. For
now, resolving most kinds of line renders it, keeping the text. Instructions
and data blocks are only rendered at the end.)
"""

import classification
import config
import disassembly
import expression
import mainformatter
import memorymanager
import movemanager
import session
import utils


class Line:
    """A line (or several lines) of output."""

    # The text, once rendered by resolve()
    _text = None

    def render(self):
        """The text for the current assembler, as a list of lines (each a
        string or a LazyString)."""
        raise NotImplementedError

    def resolve(self):
        """Make any decisions about the line that depend on what's been output
        before it (see the module docs). Called as each line is made, in
        order. Returns the line.

        By default this renders the line, keeping the text for text_lines()."""
        self._text = self.render()
        return self

    def name_labels(self):
        """Name the labels the line refers to (see disassembly.LabelRef), in
        the order they appear in its text."""
        pass

    def text_lines(self):
        """The text (as rendered by resolve(), if it has been)."""
        text = self._text
        return self.render() if text is None else text

    def plain_text(self):
        """The text without its layout (no indent, hex dump or inline
        comments), as a list of strings, one for each line. (For the JSON
        output.)"""
        return [str(line).strip() for line in self.text_lines()]


def label_refs(value):
    """The label references (see disassembly.LabelRef) in a value (an
    expression, LazyString, string or number), in the order they appear in
    its text."""
    if isinstance(value, disassembly.LabelRef):
        yield value
    elif isinstance(value, expression.InContext):
        yield from label_refs(value.value)
    elif isinstance(value, utils.LazyString):
        for arg in value._args:
            yield from label_refs(arg)
    elif isinstance(value, expression.LazyLeaf):
        yield from label_refs(value.lazy_string)
    elif isinstance(value, expression.Unary):
        yield from label_refs(value.operand)
    elif isinstance(value, expression.Binary):
        yield from label_refs(value.left)
        yield from label_refs(value.right)

def name_labels_in(value):
    """Name the labels in a value (see label_refs())."""
    for ref in label_refs(value):
        str(ref)


class Text(Line):
    """Lines of text, e.g. a table made by a function that produces text."""

    def __init__(self, lines):
        self.lines = lines

    def render(self):
        return list(self.lines)


class CommentLine(Line):
    """A one line comment (not word wrapped), e.g. '; Constants'."""

    def __init__(self, text=""):
        self.text = text

    def render(self):
        prefix = config.get_assembler().comment_prefix()
        return [prefix + " " + self.text if self.text else prefix]


class Comment(Line):
    """A comment, word wrapped, at the given indent level."""

    def __init__(self, text, indent=0):
        self.text = text
        self.indent = indent

    def render(self):
        return [mainformatter.format_comment(self.text, self.indent)]


class AnnotationLine(Line):
    """An annotation (e.g. a comment, see comment.py) that has a line of its
    own, at a binary address."""

    def __init__(self, annotation, binary_addr):
        self.annotation = annotation
        self.binary_addr = binary_addr

    def render(self):
        return [self.annotation.as_string(self.binary_addr)]


class Directive(Line):
    """An assembler directive, e.g. setting the address to assemble at, or
    the start of a block that's moved at run time.

    'name' is the name of the assembler method that writes it (e.g.
    'code_start'), and 'args' its arguments."""

    def __init__(self, name, *args):
        self.name = name
        self.args = args

    def render(self):
        result = getattr(config.get_assembler(), self.name)(*self.args)
        # (Some methods return a single line)
        return result if isinstance(result, list) else [result]


class ConstantDefinition(Line):
    """A 'name = value' definition of a constant, with an optional inline
    comment, aligned to the given columns."""

    def __init__(self, name, value, align_value_column, inline_comment, align_comment_column):
        self.name = name
        self.value = value
        self.align_value_column = align_value_column
        self.inline_comment = inline_comment
        self.align_comment_column = align_comment_column

    def render(self):
        return [mainformatter.explicit_label_with_inline_comment(self.name, self.value, None,
            align_value_column=self.align_value_column, inline_comment=self.inline_comment,
            align_comment_column=self.align_comment_column)]


class InlineLabelDefinitions(Line):
    """The definitions of a label's names that are output where the label
    is, at the runtime address 'emit_addr' (the label's own address, or an
    address just before it, for a label inside an instruction or data), for
    binary location 'binary_loc'. (Names already output aren't output again.)"""

    def __init__(self, label, emit_addr, binary_loc):
        self.label = label
        self.emit_addr = emit_addr
        self.binary_loc = binary_loc

    def render(self):
        return self.label.gather_inline_label_definitions(self.emit_addr, self.binary_loc)


class ExplicitLabelDefinitions(Line):
    """'name = value' definitions of some of a label's names (see
    Label.gather_explicit_definitions()), aligned to the given column."""

    def __init__(self, label, names, align_value_column):
        self.label = label
        self.names = names
        self.align_value_column = align_value_column

    def render(self):
        assembler = config.get_assembler()
        return [assembler.explicit_label(name, assembler.hex4(self.label.runtime_addr), offset=None, align_column=self.align_value_column)
                for name in self.names]


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
        UNDOCUMENTED   an undocumented opcode (e.g. the 8080's &CB, which runs
                       as JMP) which the assembler doesn't accept, so it's
                       written as data bytes (the opcode, then the operand, if
                       any: one byte, or the low and high bytes of a two byte
                       operand, as 'operand_length' says), with the
                       instruction it runs as in a comment

    'char_literal' is a character to show in a comment after the instruction
    (e.g. for 'lda #65', "'A'"), or None.

    The rest place the instruction in the output: its binary location and
    length (for the hex dump), its extra indent level, a description of its
    cycle count, and the annotations (for inline comments). Without a binary
    location only text() is available."""

    PLAIN          = "plain"
    FORCE_ABSOLUTE = "force absolute"
    AS_DATA        = "as data"
    UNDOCUMENTED   = "undocumented"

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

        # For UNDOCUMENTED: the operand's length in bytes
        self.operand_length = 2

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

    def text(self, plain=False):
        """The text of the instruction (indented, but without its extra
        indent level or any inline comment). (This uses the names of its
        labels, so it's only used once they can be named, i.e. after tracing.)

        If 'plain', there's no indent, and no comment (the character literal,
        or the instruction shown as AS_DATA or UNDOCUMENTED)."""

        mnemonic = utils.force_case(self.mnemonic)
        suffix = utils.force_case(self.suffix)
        assembler = config.get_assembler()

        indent = "" if plain else utils.make_indent(1)

        if self.form == Instruction.UNDOCUMENTED:
            items = [str(self.data_byte)]
            if self.operand is not None:
                if self.operand_length == 1:
                    items.append(str(self.operand))
                else:
                    import maker
                    items += [str(maker.make_lo(self.operand)), str(maker.make_hi(self.operand))]
            result = "%s%s%s" % (indent, assembler.byte_prefix(), ", ".join(items))
            if plain:
                return result
            return result + " %s %s%s (undocumented)" % (assembler.comment_prefix(), mnemonic,
                                                                 "" if self.operand is None else " " + self.prefix + str(self.operand) + suffix)

        if self.operand is None:
            return "%s%s" % (indent, mnemonic)

        if self.form == Instruction.FORCE_ABSOLUTE:
            result = assembler.force_abs_instruction(mnemonic, self.prefix, str(self.operand), suffix)
            return result.strip() if plain else result

        if self.form == Instruction.AS_DATA:
            # (The comment includes an acme-style '+2' suffix to help show
            # what's going on.)
            data_byte = str(self.data_byte)
            operand = str(self.operand)
            result = "%s%s%s, <(%s), >(%s)" % (indent, assembler.byte_prefix(), data_byte, operand, operand)
            if plain:
                return result
            return result + " ; %s+2 %s%s%s" % (mnemonic, self.prefix, self.listing_operand, suffix)

        operand = str(self.operand)
        if self.prefix == "" and operand.startswith("("):
            # (Not indirect, which some assemblers would take it to be)
            operand = assembler.direct_operand(operand)
        result = "%s%s %s%s%s" % (indent, mnemonic, self.prefix, operand, suffix)
        if self.char_literal is not None and not plain:
            result += " %s %s" % (assembler.comment_prefix(), self.char_literal)
        return result

    def name_labels(self):
        # (In the order of text(): e.g. for AS_DATA, the data byte comes first)
        if self.form == Instruction.AS_DATA:
            name_labels_in(self.data_byte)
        name_labels_in(self.operand)
        if self.form == Instruction.AS_DATA:
            name_labels_in(self.listing_operand)

    def resolve(self):
        # Name the labels in the instruction, then in any inline comments (in
        # the order they're output). It's rendered later.
        self.name_labels()
        mainformatter.inline_annotation_texts(self.binary_loc, self.length, self.annotations)
        return self

    def render(self):
        line = utils.make_indent(self.indent_level) + self.text()
        return [mainformatter.add_inline_comment_including_hexdump(self.binary_loc, self.length, self.cycles_description, self.annotations, line)]

    def plain_text(self):
        return [self.text(plain=True)]


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
        self._items = None

    def items(self):
        """The values (expressions, labels or formatted numbers). (These are
        worked out once, since getting an expression checks it, see
        classification.get_expression().)"""
        if self._items is None:
            binary_addr = self.binary_loc.binary_addr
            if self.element_size == 1:
                self._items = list(classification.get_constant8(binary_addr + i) for i in range(self.length))
            else:
                self._items = list(classification.get_constant16(binary_addr + i) for i in range(0, self.length, 2))
        return self._items

    def name_labels(self):
        for item in self.items():
            name_labels_in(item)

    def resolve(self):
        # Name the labels in the data, then in any inline comments (in the
        # order they're output). It's rendered later.
        self.name_labels()
        mainformatter.inline_annotation_texts(self.binary_loc, self.length, self.annotations)
        return self

    def render(self):
        data = self.items()
        assembler = config.get_assembler()
        data_prefix = assembler.byte_prefix() if self.element_size == 1 else assembler.word_prefix()

        prefix = utils.make_indent(1) + data_prefix         # (e.g. prefix="    !byte" for example)
        data_width = config.get_inline_comment_column() - len(prefix) - 1

        def format_line(text, start_index, end_index):
            line_binary_loc = movemanager.BinaryLocation(self.binary_loc.binary_addr + start_index*self.element_size, self.binary_loc.move_id)
            return mainformatter.add_inline_comment_including_hexdump(line_binary_loc, (end_index - start_index)*self.element_size, "", self.annotations, prefix + text)

        return utils.format_strings_in_a_table(data, data_width, self.cols, format_line)

    def plain_text(self):
        # The lines as the asm splits them, but without the padding that
        # lines up the values
        data = self.items()
        assembler = config.get_assembler()
        data_prefix = assembler.byte_prefix() if self.element_size == 1 else assembler.word_prefix()
        data_width = config.get_inline_comment_column() - len(utils.make_indent(1) + data_prefix) - 1
        def format_line(text, start_index, end_index):
            return data_prefix + ", ".join(str(x) for x in data[start_index:end_index])
        return utils.format_strings_in_a_table(data, data_width, self.cols, format_line)


class StringData(Line):
    """A string of data bytes (e.g. '.asc "Hello", 13'), split over several
    lines if it's too long for one.

    'encoding' (a textencoding.Encoding) says how its bytes are shown as
    text. If the assembler has no directive for that encoding (see
    Assembler.text_directive(), e.g. beebasm for PETSCII), the string is
    written as bytes, with its text in a comment.

    If there's an expression for its first byte (given by expr()), the
    expression is output instead of the bytes."""

    def __init__(self, binary_loc, length, annotations, encoding=None):
        import textencoding
        self.binary_loc = binary_loc
        self.length = length
        self.annotations = annotations
        self.encoding = encoding if encoding is not None else textencoding.ASCII

    def _text_form(self):
        """(directive, chr) for writing the string: the directive (e.g.
        '!pet ') and a function giving how a byte is written inside the
        string's quotes (or None to write it as a number). If the assembler
        has no directive for the encoding, it's (None, None)."""
        assembler = config.get_assembler()
        directive = assembler.text_directive(self.encoding)
        if directive is None:
            return None, None
        return directive, lambda c: assembler.text_chr(c, self.encoding)

    def name_labels(self):
        # (The labels can only be in an expression for the whole string, or
        # for a byte that's not shown as a character, see render())
        binary_addr = self.binary_loc.binary_addr
        if binary_addr in session.current().classifications.expressions:
            name_labels_in(classification.get_expression(binary_addr, session.current().memory.binary[binary_addr]))
            return
        _, text_chr = self._text_form()
        for i in range(self.length):
            c = memorymanager.get_u8_binary(binary_addr + i)
            if text_chr is None or (text_chr(c) is None and c != ord('"')):
                name_labels_in(classification.get_constant8(binary_addr + i))

    def text_comment(self, start, end):
        """The text of bytes start to end of the string (in its encoding),
        for a comment when it's written as bytes: printable runs in quotes,
        the others as numbers, e.g. '"hello", $0d'."""
        assembler = config.get_assembler()
        parts = []
        run = ""
        for i in range(start, end):
            c = memorymanager.get_u8_binary(self.binary_loc.binary_addr + i)
            char = self.encoding.char(c)
            if char is not None and char != '"':
                run += char
            else:
                if run:
                    parts.append('"%s"' % run)
                    run = ""
                parts.append(assembler.hex2(c))
        if run:
            parts.append('"%s"' % run)
        return "%s %s" % (self.encoding.name, ", ".join(parts))

    def render(self, plain=False):
        expressions = session.current().classifications.expressions
        memory_binary = session.current().memory.binary
        assembler = config.get_assembler()
        binary_loc = self.binary_loc
        annotations = self.annotations
        directive, text_chr = self._text_form()
        as_bytes = directive is None

        def finish(start, end, text):
            """The line for bytes start to end of the string"""
            line_loc = movemanager.BinaryLocation(binary_loc.binary_addr + start, binary_loc.move_id)
            if plain:
                return text.strip()
            if as_bytes:
                text += " %s %s" % (assembler.comment_prefix(), self.text_comment(start, end))
            return mainformatter.add_inline_comment_including_hexdump(line_loc, end - start, "", annotations, text, self.encoding)

        result = []
        prefix = utils.make_indent(1) + (assembler.byte_prefix() if as_bytes else directive)
        s = prefix
        state = 0       # 0=not started first string yet, 1=within string, 2=finished string
        start_line_i = 0

        if binary_loc.binary_addr in expressions:
            s = classification.get_expression(binary_loc.binary_addr, memory_binary[binary_loc.binary_addr])
            result.append(finish(0, self.length, utils.make_indent(1) + (directive if directive is not None else assembler.string_prefix()) + s))
            return result

        i = 0
        while(i < self.length):
            c = memorymanager.get_u8_binary(binary_loc.binary_addr + i)
            c_in_string = None if as_bytes else text_chr(c)

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
                if c == ord('"') and not as_bytes:
                    next_char += "'\"'"
                else:
                    next_char += classification.get_constant8(binary_loc.binary_addr + i)

            new_s = s + next_char
            len_new_s = len(new_s)
            if next_state == 1:
                len_new_s += 1
            if as_bytes:
                # (Leaving room for the comment with the text)
                len_new_s += 2 + len(assembler.comment_prefix()) + len(self.text_comment(start_line_i, i + 1))

            if len_new_s > (config.get_inline_comment_column() - 1) and i > start_line_i:
                # Save out the line before the next char
                if state == 1:
                    s += '"'
                result.append(finish(start_line_i, i, s))
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
            result.append(finish(start_line_i, self.length, s))
        return result

    def plain_text(self):
        return [str(line) for line in self.render(plain=True)]


def render_lines(lines):
    """The text for a list of line objects, as a list of lines."""
    result = []
    for line in lines:
        result.extend(line.text_lines())
    return result

def resolve(lines):
    """Resolve each of a list of lines (see Line.resolve()), returning the
    list."""
    for line in lines:
        line.resolve()
    return lines
