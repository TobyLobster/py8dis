"""
Helpers shared by acorn.py's OS call hooks (and acornosbyte.py's OSBYTE hook).
acorn.py imports them, so control files can still use acorn.enum_lookup etc.
"""

from commands import *
from classification import INSIDE_A_CLASSIFICATION
import classification
from memorymanager import BinaryAddr, RuntimeAddr
from maker import make_lo, make_hi

def xy_addr(x_addr, y_addr):
    """Given two binary addresses holding the low byte and high byte of an address,
    output expressions for each and return the address."""

    if x_addr is not None and y_addr is not None:
        assert isinstance(x_addr, BinaryAddr)
        assert isinstance(y_addr, BinaryAddr)
        if (memory_binary[x_addr] is None) or (memory_binary[y_addr] is None):
            return None
        label = get_label((memory_binary[y_addr] << 8) | memory_binary[x_addr], x_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
        x_runtime_addr = None if x_addr is None else movemanager.b2r(x_addr)
        y_runtime_addr = None if y_addr is None else movemanager.b2r(y_addr)

        if isinstance(classification.get_classification(x_addr), classification.Word) and (y_runtime_addr == (x_runtime_addr+1)):
            # If memory is classified as Word, we can have the expression be for the whole address
            auto_expr(x_runtime_addr, label)
        else:
            # If memory is classified as a byte or 'INSIDE_A_CLASSIFICATION' (e.g. an operand of an instruction) then code them as individual bytes
            if isinstance(classification.get_classification(x_addr), classification.Byte) or (classification.get_classification(x_addr) is INSIDE_A_CLASSIFICATION):
                auto_expr(x_runtime_addr, make_lo(label))
            if isinstance(classification.get_classification(y_addr), classification.Byte) or (classification.get_classification(y_addr) is INSIDE_A_CLASSIFICATION):
                auto_expr(y_runtime_addr, make_hi(label))

        return RuntimeAddr((memory_binary[y_addr] << 8) | memory_binary[x_addr])
    return None


def enum_lookup(reg_binary_addr, e, comment=None):
    """Given a binary_addr (e.g. the operand of an LDX #) and a dictionary, read
    the byte at the address and look it up in the dictionary and use the result
    to create a constant and use it as an expression. The comment, if given, is
    put on the same line. Returns the byte."""

    if reg_binary_addr is None:
        return None
    r = memorymanager.memory_binary[reg_binary_addr]
    runtime_addr = movemanager.b2r(reg_binary_addr)
    if r in e:
        constant(r, e[r])
        auto_expr(runtime_addr, e[r])
    if comment is not None:
        auto_comment(runtime_addr, comment, align=Align.INLINE)
    return r
