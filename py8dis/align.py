"""
Align

Where an annotation (e.g. a comment, see comment.py) goes in the output,
relative to the label and the line at its address. These are the values of
'align' for comment(), annotate() etc. (see docs/commands.md). A constant's
comment uses them too (see constant.py).
"""

from enum import auto, Enum
from functools import total_ordering

@total_ordering
class Align(Enum):
    """Where an annotation goes, in the order they're output:

    BEFORE_LABEL  before the label definitions at the address (if any)
    AFTER_LABEL   after them
    BEFORE_LINE   just before the line at the address (after the labels)
    INLINE        at the end of the line
    AFTER_LINE    after the line

    They compare in this order, so sorting annotations by their align puts
    them in output order (see utils.sorted_annotations())."""
    BEFORE_LABEL = auto()
    AFTER_LABEL = auto()
    BEFORE_LINE = auto()
    INLINE = auto()
    AFTER_LINE = auto()

    def __lt__(self, other):
        """Compare in output order (see above). (total_ordering makes the
        other comparisons from this.)"""
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented
