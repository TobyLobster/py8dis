import utils
import config
from align import Align

class Annotation:
    """A raw string to add to the output."""

    def __init__(self, text, align=Align.INLINE, priority=None, auto_generated=False):
        if priority is None:
            priority = 0
        self.text = text
        self.priority = priority
        self.align = align
        self.auto_generated = auto_generated

    def as_string(self, binary_addr):
        return str(self.text)

    def __str__(self):
        return str(self.text)

    def __repr__(self) -> str:
        return self.__str__()

class Comment(Annotation):
    """A comment, either inline or standalone.

    Derives from the Annotation class. The text (which may be a LazyString,
    e.g. containing a label that isn't named yet) is formatted as a comment
    when it's first output: word wrapped (unless it's inline or word_wrap is
    False) at the given indent level."""

    def __init__(self, text, word_wrap=True, indent=0, align=Align.BEFORE_LABEL, priority=None, auto_generated=True):
        Annotation.__init__(self, text, align=align, priority=priority, auto_generated=auto_generated)
        self.word_wrap = word_wrap
        self.indent = indent
        self._formatted = None

    def as_string(self, binary_addr):
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
    dump of its bytes. 'instruction_text' is the instruction's text (see
    output.Instruction.text()), which may have labels that aren't named yet."""

    def __init__(self, binary_loc, length, instruction_text):
        Annotation.__init__(self, instruction_text, align=Align.BEFORE_LABEL)
        self.binary_loc = binary_loc
        self.length = length
        self._formatted = None

    def as_string(self, binary_addr):
        if self._formatted is None:
            import mainformatter    # (see Comment.as_string())
            text = config.get_assembler().comment_prefix() + " overlapping: " + str(self.text)[4:]
            self._formatted = mainformatter.add_inline_comment_including_hexdump(self.binary_loc, self.length, "", None, text)
        return self._formatted

    def __str__(self):
        return self.as_string(None)
