"""
Comments and annotations

An 'annotation' is something extra in the output at a binary location,
besides the classification there (see classification.py): a comment
(Comment), raw text for the assembler (Annotation, from annotate()), or an
instruction found while tracing that overlaps the code or data already
there, shown in a comment (OverlappingInstruction).

disassembly.py keeps them in a list for each memorymanager.BinaryLocation,
in the session's disassembly.annotations (see disassembly.comment_binary()
and add_annotation()). Each has an 'align' (see align.py) that says where it
goes: before or after the label at its address, before or after the line
there, or inline, at the end of the line. A 'priority' orders those with the
same align, lowest first, then the order they were added (see
utils.sorted_annotations()). An auto_generated one (made by py8dis, rather
than given by the control file) is left out if it's the same as the one
before it.

as_string() gives the text to output. Inline ones are added to the end of
the line by mainformatter.add_inline_comment_including_hexdump(); the
others are lines of their own (output.AnnotationLine). Before the output is
made, name_labels() names any labels the text uses (see
disassembly.fix_label_names()).
"""

import utils
import config
from align import Align

class Annotation:
    """A raw string to add to the output.

    It's output as it is, so it has to be something the assembler
    understands (see annotate() in docs/commands.md). This is also the base
    class of the other annotations, which format their text.

    'text' is a string, or something that becomes one with str() (e.g. a
    LazyString holding a label that isn't named yet). 'align' and
    'priority' say where it goes (see the module docs): a 'priority' of
    None is 0. 'auto_generated' is True if py8dis made it."""

    def __init__(self, text, align=Align.INLINE, priority=None, auto_generated=False):
        if priority is None:
            priority = 0
        self.text = text
        self.priority = priority
        self.align = align
        self.auto_generated = auto_generated

    def as_string(self, binary_addr):
        """The text to output. ('binary_addr', where it's output, isn't
        used here or by the subclasses.)"""
        return str(self.text)

    def name_labels(self):
        """Name the labels the annotation refers to (see output.label_refs())."""
        import output       # (see Comment.as_string())
        output.name_labels_in(self.text)

    def __str__(self):
        return str(self.text)

    def __repr__(self) -> str:
        return self.__str__()

class Comment(Annotation):
    """A comment, either inline or standalone.

    Derives from the Annotation class. The text (which may be a LazyString,
    e.g. containing a label that isn't named yet) is formatted as a comment
    when it's first output: word wrapped (unless it's inline or word_wrap is
    False) at the given indent level. The formatted text is kept, so it's
    only formatted once.

    'auto_generated' is True by default here: the callers say False for a
    comment from the control file (e.g. comment())."""

    def __init__(self, text, word_wrap=True, indent=0, align=Align.BEFORE_LABEL, priority=None, auto_generated=True):
        Annotation.__init__(self, text, align=align, priority=priority, auto_generated=auto_generated)
        self.word_wrap = word_wrap
        self.indent = indent
        self._formatted = None

    def as_string(self, binary_addr):
        """The comment: word wrapped by mainformatter.format_comment()
        (unless it's inline or word_wrap is False), or else each line of the
        text after the indent and the assembler's comment prefix (e.g.
        ';')."""
        if self._formatted is None:
            # (Imported here, since mainformatter imports (indirectly) the
            # disassembly module, which imports this one.)
            import mainformatter

            strtext = str(self.text)
            if self.word_wrap and self.align != Align.INLINE:
                self._formatted = mainformatter.format_comment(strtext, self.indent)
            else:
                self._formatted = "\n".join("{0}{1} {2}".format(config.get_indent_string() * self.indent, config.get_assembler().comment_prefix(), line) for line in strtext.split("\n"))
        return self._formatted

    def __str__(self):
        return self.as_string(None)


class OverlappingInstruction(Annotation):
    """A comment showing an instruction found while tracing which overlaps
    code or data already there, e.g. '; overlapping: lda #3', with the hex
    dump of its bytes. 'instruction' is the instruction (an
    output.Instruction), whose labels aren't named yet.

    'binary_loc' and 'length' are where its bytes are, for the hex dump.
    It goes before the label at its address. (These are made by
    cpu.Cpu.disassemble_instruction().)"""

    def __init__(self, binary_loc, length, instruction):
        Annotation.__init__(self, instruction, align=Align.BEFORE_LABEL)
        self.binary_loc = binary_loc
        self.length = length
        self._formatted = None

    def name_labels(self):
        """Name the labels the instruction uses."""
        self.text.name_labels()

    def as_string(self, binary_addr):
        """The comment, e.g. '; overlapping: lda #3', with the hex dump of the
        instruction's bytes. It's formatted the first time, and kept."""
        if self._formatted is None:
            import mainformatter    # (see Comment.as_string())
            # ([4:] removes the instruction's indent, if it's the default of
            # 4 spaces: see config.set_indent_string())
            text = config.get_assembler().comment_prefix() + " overlapping: " + self.text.text()[4:]
            self._formatted = mainformatter.add_inline_comment_including_hexdump(self.binary_loc, self.length, "", None, text)
        return self._formatted

    def __str__(self):
        return self.as_string(None)
