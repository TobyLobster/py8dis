"""
Binary address type

The BinaryAddrType enum. When py8dis (or a control file, with get_label())
asks for a label for a runtime address, it also gives a binary address for
context, and a BinaryAddrType saying what that binary address is: where the
label is used, or where it's defined. The label's name can depend on where
it's used (e.g. a local label, or a label maker hook that names labels by
where they're used, see LabelMakingData.in_range()). The type goes with the
binary address to the label maker (see disassembly.suggest_label_name()) and
to the hook, and some names only apply to a use (see
disassembly._range_optional_label()).
"""

from enum import Enum, auto

class BinaryAddrType(Enum):
    """Enum representing the different binary address types when making a
    label: what the binary address given with a label's runtime address is
    (see the top of this file)."""
    BINARY_ADDR_IS_AT_LABEL_USAGE = auto()        # The binary address is the location of a use of the label e.g. the address of an operand to an 'LDA addr' instruction
    BINARY_ADDR_IS_AT_LABEL_DEFINITION = auto()   # The binary address corresponds to the runtime address where the label would be defined.
