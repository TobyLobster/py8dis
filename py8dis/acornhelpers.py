"""
Acorn helpers

Helpers for the subroutine hooks that comment calls to an OS: acorn.py's
(and acornosbyte.py's OSBYTE hook), and commodore.py's too. Given where a
register is loaded with an immediate value before a call, they write that
value as a name: xy_addr() as the label of the address that two registers
hold (e.g. 'ldx #<block : ldy #>block' for the address of an OSWORD
parameter block), and enum_lookup() as a constant's name from a dictionary
(e.g. 'lda #osbyte_read_os_version').

acorn.py imports them, so control files can use them as acorn.xy_addr and
acorn.enum_lookup too.
"""

from commands import *
from classification import INSIDE_A_CLASSIFICATION
import classification
from memorymanager import BinaryAddr, RuntimeAddr
from maker import make_lo, make_hi

def xy_addr(x_addr, y_addr):
    """The address whose low byte is at binary address x_addr and high byte at
    y_addr (usually the operands of 'ldx #lo' and 'ldy #hi' before an OS
    call), as a RuntimeAddr, with those bytes written as the label of that
    address. Returns None if either binary address is None, or nothing is
    loaded there.

    The label is found with get_label(), so one is made (auto-generated) if
    there isn't one. If x_addr is classified as a word and y_addr is the next
    byte, the word is written as the label; otherwise each byte that's byte
    data or part of an instruction is written as the label's low or high
    byte (e.g. 'ldx #<block')."""

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
    """Name the byte at reg_binary_addr (e.g. the operand of 'ldx #nn') from
    the dictionary 'e' ({value: name}, e.g. acorn.osbyte_enum), and return
    the byte, or None if reg_binary_addr is None.

    If the byte is in the dictionary, its name is defined as a constant
    (listed at the top of the output) and the byte is written as the name.
    The comment, if given, is added at the end of the line, whether or not
    the byte has a name."""

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
