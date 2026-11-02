"""
Output

The disassembly is described by a list of line objects, which say what to
output rather than holding text: an instruction (its mnemonic and operand), a
block of data bytes or words, a string, a comment, label definitions, an
assembler directive, a blank line. render_lines() turns them into text for
the current assembler (see assembler.py), whose methods say how each part is
written.

disassembly.emit() builds the whole output as a list of these lines: a
header (the assembler's disassembly_start(), the constants and the "Memory
locations"), the main disassembly, then a footer (the assembler's
disassembly_end(), with the assertions, and tables such as the label
references). In the main disassembly, each classification (an instruction,
bytes, words or a string, see classification.py) makes its own lines with
its as_lines() method: an Instruction (made by the CPU's Opcode class),
a DataBlock or a StringData. emit() adds the labels and comments around
them, and a Directive wherever the assembler needs one (e.g. code_start(),
which sets the address to assemble at).

Each line is resolved as it's made (see Line.resolve()): this makes any
decisions that depend on what's been output so far, e.g. naming labels used
for the first time (in e.g. comments), and choosing which label definitions
are output where. Then the lines are rendered, and emit() joins the text
(after the assembler's tidy_output() and sanitise_line()).

Layout: a line of an instruction, data or a string is indented, and padded
to the inline comment column (config.set_inline_comment_column()), where
there's a comment with its hex dump (its binary address, bytes and their
characters, the cycle count and CPU state if they're shown, and the runtime
address of moved code) and any inline comments: see
mainformatter.add_inline_comment_including_hexdump(). A comment on a line of
its own is word wrapped (see Comment, and comment.py).

The JSON output (see jsonoutput.py) uses the same line objects:
plain_text() gives a line's text as in the asm, without its layout.

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
    """A line (or several lines) of output: the base class of the kinds of
    line below."""

    # The text, once rendered by resolve()
    _text = None

    def render(self):
        """The text for the current assembler, as a list of lines (each a
        string or a LazyString). A string can hold more than one line,
        separated by newlines (e.g. a word wrapped comment)."""
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
        the order they appear in its text. (Naming a label fixes its name the
        first time it's used. By default there are none.)"""
        pass

    def text_lines(self):
        """The text, as a list of lines (as rendered by resolve(), if it has
        been, otherwise rendered now)."""
        text = self._text
        return self.render() if text is None else text

    def plain_text(self):
        """The text without its layout (no indent, hex dump or inline
        comments), as a list of strings, one for each line. (For the JSON
        output.) By default this is the text with the spaces at each end
        taken off."""
        return [str(line).strip() for line in self.text_lines()]


def label_refs(value):
    """The label references (see disassembly.LabelRef) in a value (an
    expression, LazyString, string or number), in the order they appear in
    its text. (A generator: it looks inside expressions and LazyStrings for
    them.)"""
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
    """Name the labels in a value (see label_refs()), in order."""
    for ref in label_refs(value):
        # (Making its text names the label, if it isn't named yet)
        str(ref)


class Text(Line):
    """Lines of text, already made, e.g. a table made by a function that
    produces text (such as the label references at the end). 'lines' is a
    list of strings."""

    def __init__(self, lines):
        self.lines = lines

    def render(self):
        """The lines as they are."""
        return list(self.lines)


class CommentLine(Line):
    """A one line comment (not word wrapped), e.g. '; Constants'. With no
    text, it's just the comment prefix."""

    def __init__(self, text=""):
        self.text = text

    def render(self):
        """The comment prefix, then the text."""
        prefix = config.get_assembler().comment_prefix()
        return [prefix + " " + self.text if self.text else prefix]


class Comment(Line):
    """A comment, word wrapped (see mainformatter.format_comment()), at the
    given indent level."""

    def __init__(self, text, indent=0):
        self.text = text
        self.indent = indent

    def render(self):
        """The word wrapped comment, as one string with newlines."""
        return [mainformatter.format_comment(self.text, self.indent)]


class AnnotationLine(Line):
    """An annotation (e.g. a comment, see comment.py) that has a line of its
    own, at a binary address. The annotation formats itself (see its
    as_string())."""

    def __init__(self, annotation, binary_addr):
        self.annotation = annotation
        self.binary_addr = binary_addr

    def render(self):
        """The annotation's text."""
        return [self.annotation.as_string(self.binary_addr)]


class Directive(Line):
    """An assembler directive, e.g. setting the address to assemble at, or
    the start of a block that's moved at run time.

    'name' is the name of the assembler method that writes it (e.g.
    'code_start', see assembler.py), and 'args' its arguments. The method is
    called when the line is resolved (i.e. as soon as it's made)."""

    def __init__(self, name, *args):
        self.name = name
        self.args = args

    def render(self):
        """The lines the assembler's method gives."""
        result = getattr(config.get_assembler(), self.name)(*self.args)
        # (Some methods return a single line, e.g. include_binary_file())
        return result if isinstance(result, list) else [result]


class ConstantDefinition(Line):
    """A 'name = value' definition of a constant (see
    mainformatter.explicit_label_with_inline_comment()), with an optional
    inline comment, aligned to the given columns: the name is padded to
    'align_value_column' (so that the values of a list of them line up), and
    the comment starts at 'align_comment_column'."""

    def __init__(self, name, value, align_value_column, inline_comment, align_comment_column):
        self.name = name
        self.value = value
        self.align_value_column = align_value_column
        self.inline_comment = inline_comment
        self.align_comment_column = align_comment_column

    def render(self):
        """The definition, with its comment."""
        return [mainformatter.explicit_label_with_inline_comment(self.name, self.value, None,
            align_value_column=self.align_value_column, inline_comment=self.inline_comment,
            align_comment_column=self.align_comment_column)]


class InlineLabelDefinitions(Line):
    """The definitions of a label's names that are output where the label
    is, at the runtime address 'emit_addr' (the label's own address, or an
    address just before it, for a label inside an instruction or data), for
    binary location 'binary_loc'. (Names already output aren't output again.)

    The label works out its definitions (see
    Label.gather_inline_label_definitions()) when the line is resolved, which
    marks the names as output, so it has to happen in output order."""

    def __init__(self, label, emit_addr, binary_loc):
        self.label = label
        self.emit_addr = emit_addr
        self.binary_loc = binary_loc

    def render(self):
        """The definitions (e.g. '.loop'), marking the names as output."""
        return self.label.gather_inline_label_definitions(self.emit_addr, self.binary_loc)


class ExplicitLabelDefinitions(Line):
    """'name = value' definitions of some of a label's names (see
    Label.gather_explicit_definitions()), aligned to the given column, with
    the label's runtime address as the value (in hex, see hex4()). These are
    the "Memory locations" at the top of the output (see
    disassembly.memory_location_definitions())."""

    def __init__(self, label, names, align_value_column):
        self.label = label
        self.names = names
        self.align_value_column = align_value_column

    def render(self):
        """A 'name = value' line for each name."""
        assembler = config.get_assembler()
        return [assembler.explicit_label(name, assembler.hex4(self.label.runtime_addr), offset=None, align_column=self.align_value_column)
                for name in self.names]


class Blank(Line):
    """A blank line."""

    def render(self):
        """An empty line."""
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
    cycle count, and the annotations (the session's, see disassembly.py, for
    the inline comments on its bytes). Without a binary location only text()
    is available. (The CPU modules make an Instruction for an opcode, then
    give these with placed().)"""

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

        # For UNDOCUMENTED: all the instruction's bytes as data items (the
        # Z80's), if given, instead of 'data_byte' and the operand; and the
        # comment, if not the instruction
        self.data_items = None
        self.comment_text = None

        self.binary_loc = binary_loc
        self.length = length
        self.indent_level = indent_level
        self.cycles_description = cycles_description
        self.annotations = annotations

    def placed(self, binary_loc, length, indent_level, cycles_description, annotations):
        """Set where the instruction is in the output (see the class docs).
        Returns the instruction."""
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
            # Data bytes (all the instruction's, as data items, or the opcode
            # then the operand's), then the instruction in a comment
            if self.data_items is not None:
                items = [str(x) for x in self.data_items]
            else:
                items = [str(self.data_byte)]
            if self.data_items is None and self.operand is not None:
                if self.operand_length == 1:
                    items.append(str(self.operand))
                else:
                    import maker
                    items += [str(maker.make_lo(self.operand)), str(maker.make_hi(self.operand))]
            result = "%s%s%s" % (indent, assembler.byte_prefix(), ", ".join(items))
            if plain:
                return result
            if self.comment_text is not None:
                return result + " %s %s (undocumented)" % (assembler.comment_prefix(), self.comment_text)
            return result + " %s %s%s (undocumented)" % (assembler.comment_prefix(), mnemonic,
                                                                 "" if self.operand is None else " " + self.prefix + str(self.operand) + suffix)

        if self.operand is None:
            return "%s%s" % (indent, mnemonic)

        if self.form == Instruction.FORCE_ABSOLUTE:
            result = assembler.force_abs_instruction(mnemonic, self.prefix, str(self.operand), suffix)
            return result.strip() if plain else result

        if self.form == Instruction.AS_DATA:
            # The opcode, then the operand's low and high bytes. (The comment
            # includes an acme-style '+2' suffix to help show what's going
            # on.)
            data_byte = str(self.data_byte)
            operand = str(self.operand)
            result = "%s%s%s, <(%s), >(%s)" % (indent, assembler.byte_prefix(), data_byte, operand, operand)
            if plain:
                return result
            return result + " %s %s+2 %s%s%s" % (assembler.comment_prefix(), mnemonic, self.prefix, self.listing_operand, suffix)

        # PLAIN
        operand = str(self.operand)
        if self.prefix == "" and operand.startswith("("):
            # (Not indirect, which some assemblers would take it to be)
            operand = assembler.direct_operand(operand)
        result = "%s%s %s%s%s" % (indent, mnemonic, self.prefix, operand, suffix)
        if self.char_literal is not None and not plain:
            result += " %s %s" % (assembler.comment_prefix(), self.char_literal)
        return result

    def name_labels(self):
        """Name the labels in the opcode byte (for AS_DATA), the operand and
        the instruction in the comment (for AS_DATA)."""
        # (In the order of text(): e.g. for AS_DATA, the data byte comes first)
        if self.form == Instruction.AS_DATA:
            name_labels_in(self.data_byte)
        name_labels_in(self.operand)
        if self.form == Instruction.AS_DATA:
            name_labels_in(self.listing_operand)

    def resolve(self):
        """Name the labels in the instruction, then in any inline comments
        (in the order they're output). It's rendered later."""
        self.name_labels()
        # (Getting the comments' text names their labels)
        mainformatter.inline_annotation_texts(self.binary_loc, self.length, self.annotations)
        return self

    def render(self):
        """The instruction, at its extra indent level, then its inline
        comment: the hex dump and any inline comments."""
        line = utils.make_indent(self.indent_level) + self.text()
        return [mainformatter.add_inline_comment_including_hexdump(self.binary_loc, self.length, self.cycles_description, self.annotations, line)]

    def plain_text(self):
        """The text(plain=True): no indent or comments."""
        return [self.text(plain=True)]


class DataBlock(Line):
    """A block of data bytes or words, laid out as a table (e.g. several
    '!byte' lines, each with some number of values), each line with its own
    hex dump.

    'binary_loc' is where it starts, 'element_size' is 1 for bytes or 2 for
    words, and 'length' is in bytes. 'cols' is the number of values per line,
    or None to fit as many as possible before the inline comment column.
    'annotations' are the session's (for the inline comments)."""

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
        """Name the labels in the values, in order."""
        for item in self.items():
            name_labels_in(item)

    def resolve(self):
        """Name the labels in the data, then in any inline comments (in the
        order they're output). It's rendered later."""
        self.name_labels()
        # (Getting the comments' text names their labels)
        mainformatter.inline_annotation_texts(self.binary_loc, self.length, self.annotations)
        return self

    def render(self):
        """The lines of the table: the values, comma separated and lined up
        in columns (see utils.format_strings_in_a_table()), each line with
        the hex dump and inline comments for its own bytes."""
        data = self.items()
        assembler = config.get_assembler()
        data_prefix = assembler.byte_prefix() if self.element_size == 1 else assembler.word_prefix()

        prefix = utils.make_indent(1) + data_prefix         # (e.g. prefix="    !byte" for example)
        # (The room for the values, leaving a space before the inline comment)
        data_width = config.get_inline_comment_column() - len(prefix) - 1

        def format_line(text, start_index, end_index):
            """The line for the values from start_index up to end_index (as
            'text'), with the hex dump and inline comments for their bytes."""
            line_binary_loc = movemanager.BinaryLocation(self.binary_loc.binary_addr + start_index*self.element_size, self.binary_loc.move_id)
            return mainformatter.add_inline_comment_including_hexdump(line_binary_loc, (end_index - start_index)*self.element_size, "", self.annotations, prefix + text)

        return utils.format_strings_in_a_table(data, data_width, self.cols, format_line)

    def plain_text(self):
        """The lines as the asm splits them, but without the indent, the
        padding that lines up the values, or the comments."""
        data = self.items()
        assembler = config.get_assembler()
        data_prefix = assembler.byte_prefix() if self.element_size == 1 else assembler.word_prefix()
        data_width = config.get_inline_comment_column() - len(utils.make_indent(1) + data_prefix) - 1
        def format_line(text, start_index, end_index):
            """The values from start_index up to end_index, without the
            padding in 'text'."""
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
    expression is output instead of the bytes.

    A string is written as runs of characters in double quotes, with the
    bytes that can't be in them (see Assembler.text_chr()) as numbers
    between, e.g. '"Hello", 13'. Each line has its own hex dump (for its
    own bytes)."""

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
        """Name the labels in the string's expression, or in the bytes
        written as numbers."""
        # (The labels can only be in an expression for the whole string, or
        # for a byte that's not shown as a character, see render(). A double
        # quote is written as a character literal, see _render().)
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
        """The text of bytes start to end (not included) of the string, for a
        comment when it's written as bytes: the encoding's name, then the
        runs of characters it has in quotes, and the other bytes (and double
        quotes) as hex numbers, e.g. 'petscii "hello", $0d'."""
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
        """The lines of the string (see _render()), with any lines the
        assembler wants before and after a string in its encoding (unless
        'plain')."""
        result = self._render(plain)
        directive, _ = self._text_form()
        if plain or directive is None:
            return result
        # (e.g. 64tass's '.enc', for a string in an encoding of its own)
        before, after = config.get_assembler().text_encoding_lines(self.encoding)
        return before + result + after

    def _render(self, plain):
        """The lines of the string: the directive, then its characters and
        numbers, starting a new line before one would reach the inline
        comment column. If 'plain', the lines have no indent or comments
        (for the JSON output)."""
        expressions = session.current().classifications.expressions
        memory_binary = session.current().memory.binary
        assembler = config.get_assembler()
        binary_loc = self.binary_loc
        annotations = self.annotations
        directive, text_chr = self._text_form()
        as_bytes = directive is None

        def finish(start, end, text):
            """The line for bytes start to end (not included) of the string,
            whose text so far is 'text': with the text in a comment if it's
            written as bytes, then its hex dump and inline comments."""
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

        # An expression for the whole string (e.g. a constant's name) is
        # written in place of its bytes, on one line
        if binary_loc.binary_addr in expressions:
            s = classification.get_expression(binary_loc.binary_addr, memory_binary[binary_loc.binary_addr])
            result.append(finish(0, self.length, utils.make_indent(1) + (directive if directive is not None else assembler.string_prefix()) + s))
            return result

        # Add each byte to the line in turn, until the next one wouldn't fit
        # (start_line_i is the index of the line's first byte)
        i = 0
        while(i < self.length):
            c = memorymanager.get_u8_binary(binary_loc.binary_addr + i)
            c_in_string = None if as_bytes else text_chr(c)

            # Calculate how to add 'c' to  the current assembly string in 'next_char'
            next_char = ""
            next_state = state
            if c_in_string is not None:
                # A character in the quotes, opening them if needed
                if state == 0:
                    next_char += '"'
                elif state == 2:
                    next_char += ', "'
                next_state = 1
                next_char += c_in_string
            else:
                # A number, closing the quotes if needed
                if state == 1:
                    next_char += '", '
                elif state == 2:
                    next_char += ", "
                next_state = 2
                if c == ord('"') and not as_bytes:
                    # (A double quote as a character literal)
                    next_char += "'\"'"
                else:
                    next_char += classification.get_constant8(binary_loc.binary_addr + i)

            new_s = s + next_char
            len_new_s = len(new_s)
            if next_state == 1:
                # (Leaving room for the closing quote)
                len_new_s += 1
            if as_bytes:
                # (Leaving room for the comment with the text)
                len_new_s += 2 + len(assembler.comment_prefix()) + len(self.text_comment(start_line_i, i + 1))

            # (A line always gets at least one byte, even if it's too long)
            if len_new_s > (config.get_inline_comment_column() - 1) and i > start_line_i:
                # Save out the line before the next char, which is added
                # again on a new line
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

        # The last line
        if s != prefix:
            if state == 1:
                s += '"'
            result.append(finish(start_line_i, self.length, s))
        return result

    def plain_text(self):
        """The lines as render(plain=True) makes them: without the indent,
        comments or encoding lines."""
        return [str(line) for line in self.render(plain=True)]


def render_lines(lines):
    """The text for a list of line objects, as a list of lines (strings or
    LazyStrings; a string can hold several lines, separated by newlines)."""
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
