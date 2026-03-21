"""
Classifies every byte of a binary file.

Bytes that are loaded from a binary file are classified by type. Data
is marked with a Byte, Word or String object, and code is marked with
an Opcode* object, as defined by the configured CPU.

Each classification object has a length, so the object is stored in the
first address of the classification, and the remainder are set to the
'INSIDE_A_CLASSIFICATION' constant so it's known to be classified.

Users can mark data as Byte, Word or String. They use functions
byte() and word() for the first two types. For strings there are a
number of functions to help determine the full extent of the string:

stringterm()  the string terminates at a specified termination value
stringcr()    the string terminates at ASCII code 13
stringz()     the string terminates at ASCII code 0
string()      the string terminates at a non-printable character, or
              the given length
stringhi()    the string terminates at a top-bit-set character,
              optionally including the bottom 7 bits of the terminator
              as the final character
stringhiz()   as stringhi, but also terminates at zero
stringn()     the first byte holds the length, followed by the string

An included binary file is marked as type Byte.

This module also manages 'Expressions'. Expressions are user defined
output strings associated with an address. They are typically used for
applying some calculation or arithmetic to the immediate operands of
instructions, or to data.

e.g. An expression 'initial_lives + 1' could be used to output an
instruction 'LDA #initial_lives + 1'. The address supplied for the
expression must be of the operand, not the opcode.
"""

from __future__ import print_function
import collections
import config
import copy
import disassembly
import labelmanager
import mainformatter
import memorymanager
import movemanager
import pprint
import stats
import trace
import traceback
import utils
from memorymanager import BinaryAddr, RuntimeAddr
from format import Format
from binaryaddrtype import BinaryAddrType

expressions   = {}
memory_binary = memorymanager.memory_binary
assembler     = config.get_assembler

# `classifications` stores classifications indexed by binary address.
classifications = [None] * 64*1024

# Dictionary of binary files to include in the output, keyed by binary address
include_binary_files = dict()

# Remember the addresses where a split_classification is requested
split_classifications = set()

# `INSIDE_A_CLASSIFICATION` is an arbitrary constant value.
#
# We assign this value to the second and subsequent bytes of a multi-byte
# classification (e.g. the operands of an instruction). Its actual value doesn't
# matter, as long as it's not None so we know these bytes have been classified.
INSIDE_A_CLASSIFICATION = 0

# ENHANCE: At the moment there's no support for wrapping round at the top of
# memory and we might just crash (probably with an out-of-bounds error) if
# disassembling right up to the top of memory.

class Byte(object):
    """Object used to mark part of the binary data as bytes."""

    def __init__(self, length, cols=None):
        assert length > 0
        assert cols is None or cols > 0
        self._length = length
        self._cols = cols

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        self._length = length

    def is_code(self, binary_addr):
        return False

    def as_string_list(self, binary_loc, annotations):
        return mainformatter.format_data_block(binary_loc, self._length, self._cols, 1, annotations)


class Word(object):
    """Object used to mark part of the binary data as words (16 bit)."""

    def __init__(self, length, cols=None):
        assert cols is None or cols > 0
        self.set_length(length)
        self._cols = cols

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        assert length % 2 == 0
        self._length = length

    def is_code(self, binary_addr):
        return False

    def as_string_list(self, binary_loc, annotations):
        return mainformatter.format_data_block(binary_loc, self._length, self._cols, 2, annotations)


class String(object):
    """Object used to mark part of the binary data as a string."""

    def __init__(self, length):
        assert length > 0
        self._length = length
        self._caller = utils.find_external_callstack()

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        self._length = length

    def is_code(self, binary_addr):
        return False

    def as_string_list(self, binary_loc, annotations):
        result = []
        prefix = utils.make_indent(1) + assembler().string_prefix()
        s = prefix
        state = 0       # 0=not started first string yet, 1=within string, 2=finished string
        start_line_i = 0

        if binary_loc.binary_addr in expressions:
            s = get_expression(binary_loc.binary_addr, memory_binary[binary_loc.binary_addr])
            result.append(mainformatter.add_inline_comment_including_hexdump(binary_loc, self._length, "", annotations, prefix + s))
            return result

        i = 0
        while(i < self._length):
            c = memorymanager.get_u8_binary(binary_loc.binary_addr + i)
            c_in_string = assembler().string_chr(c)

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
                    next_char += get_constant8(binary_loc.binary_addr + i)

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
            result.append(mainformatter.add_inline_comment_including_hexdump(temp_binary_loc, self._length - start_line_i, "", annotations, s))
        return result

    def __str__(self):
        #formatted_string = pprint.pformat(self._caller, indent=0)
        formatted_string = ""
        for i in self._caller:
            formatted_string = str(i) + "\n" + formatted_string
        return "String, of length {0}, during call from:\n{1}".format(self._length, formatted_string)

    def __repr__(self) -> str:
        return self.__str__()

def init():
    classifications = [None] * 64*1024
    split_classifications = set()
    include_binary_files = dict()

def add_expression(binary_addr, s, *, force=True):
    """Add an expression for the given binary address."""

    assert not isinstance(s, labelmanager.Label) # TODO!?
    # TODO: Warn/assert if binary_addr already in expressions? Allow overriding this via an optional bool argument?
    has_existing_expr = binary_addr in expressions
    if (force or not has_existing_expr) and not (binary_addr in trace.no_auto_comment_set):
        expressions[binary_addr] = s

    # Returns the current expression
    return expressions[binary_addr]

def check_expr(expr, value, message):
    """Add an assert to the output based on an expression."""

    # ENHANCE: It would be good to at least try to evaluate "expression" and generate
    # an error if it doesn't match expected_value. In reality most expressions will
    # be fairly simple combinations of labels and basic integer arithmetic, mixed with
    # the < and > operators to get the low and high bytes of a 16-bit word.

    # ENHANCE: It would be good if this could (probably optionally) evaluate
    # 'expr' itself in the content of the current set of labels and constants.
    # However, the "assert at assembly time" approach should be absolutely
    # reliable (it's just not as early a detection as we'd like) so should
    # probably be retained even if expression evaluation is supported directly
    # in py8dis.

    # Don't clutter the output with pedantic 'constant = value' assertions
    for constant in disassembly.constants:
        if expr == constant.name:
            if constant.format == Format.CHAR:
                return
            elif constant.format == Format.STRING:
                return
            elif (constant.value != value):
                utils.die("Constant '{0}' found to be {1} but expected to be {2} {3}".format(expr, constant.value, value, message))
            return

    config.get_assembler().assert_expr(expr, value)

def get_expression(binary_addr, expected_value):
    """Get the previously supplied expression for the given address."""

    expression = expressions[binary_addr]
    c = get_classification(binary_addr)
    if isinstance(c, String):
        length = c.length()
        string_at_binary = ""
        for i in range(length):
            string_at_binary += chr(memory_binary[binary_addr])
            binary_addr += 1
        expected_value = string_at_binary
    check_expr(expression, expected_value, "at {0}".format(hex(binary_addr)))

    return expression

def add_classification(binary_addr, c):
    """Sets the classification for the given address.

    A classification has a length in bytes. The first byte is
    classified with the given classification and all following bytes
    are marked with `INSIDE_A_CLASSIFICATION`.
    """

    binary_addr = BinaryAddr(binary_addr)
    assert c is not None
    assert not is_classified(binary_addr, c.length()), "Binary address {0} is already classified as {1}".format(hex(binary_addr), get_classification(binary_addr))

    prev_addr = binary_addr
    classifications[binary_addr] = copy.copy(c)
    for i in range(1, c.length()):
        current_addr = binary_addr+i
        if current_addr in split_classifications:
            classifications[prev_addr].set_length(current_addr-prev_addr)
            classifications[current_addr] = copy.copy(c)
            classifications[current_addr].set_length(c.length() - i)
            prev_addr = current_addr
        else:
            classifications[current_addr] = INSIDE_A_CLASSIFICATION

def get_classification(binary_addr):
    return classifications[binary_addr]

def is_classified(binary_addr, length=1):
    """Is any address in the given range classified?"""

    return any(x is not None for x in classifications[binary_addr:binary_addr+length])

def is_code(binary_addr):
    """Is the given `binary_addr` classified as an instruction opcode?"""

    c = classifications[binary_addr]
    if c is None or c == INSIDE_A_CLASSIFICATION:
        return False
    return c.is_code(binary_addr)

def split_classification(binary_addr, *, warn):
    """If e.g. a move boundary is in the middle of an instruction, then split the classification."""

    if binary_addr >= 0x10000:
        return

    # Remember the split addresses for later, so that we can avoid adding a string across the split.
    split_classifications.add(binary_addr)

    if classifications[binary_addr] != INSIDE_A_CLASSIFICATION:
        return

    # TODO: Do we need to check and not warn if this is just an automatic string/byte classification?
    if warn:
        utils.warn("move boundary at binary address {0} splits a classification".format(config.get_assembler().hex(binary_addr)))
    split_addr = binary_addr
    while classifications[binary_addr] == INSIDE_A_CLASSIFICATION:
        binary_addr -= 1

    # classify as bytes
    first_split_length = split_addr - binary_addr
    classifications[split_addr] = Byte(classifications[binary_addr].length() - first_split_length)
    classifications[binary_addr] = Byte(first_split_length)

def classify_leftovers():
    """Classify everything not already classified, as bytes."""

    binary_addr = BinaryAddr(0)
    while binary_addr < len(memory_binary):
        i = 0
        while (binary_addr + i) < len(memory_binary) and memory_binary[binary_addr + i] is not None and not is_classified(binary_addr + i, 1):
            i += 1
            if (binary_addr + i) >= len(memory_binary) or movemanager.b2r(binary_addr + i) in labelmanager.labels:
                break
        if i > 0:
            add_classification(binary_addr, Byte(i))
        binary_addr += max(1, i)

# TODO: I've made this work with runtime_addr without paying any attention to the needs of hook fns etc
def stringterm_binary(binary_addr, terminator, exclude_terminator=False):
    """Classifies part of the binary as a string followed by a given
    terminator byte.

    Returns the next available memory address after the string."""

    initial_addr = binary_addr
    while memory_binary[binary_addr] != terminator:
        binary_addr += 1
    string_length = (binary_addr + 1) - initial_addr
    if exclude_terminator:
        string_length -= 1
    if string_length > 0:
        add_classification(initial_addr, String(string_length))
    return movemanager.b2r(binary_addr + 1)

def string_binary(binary_addr, n):
    if n is None:
        assert not is_classified(binary_addr), "Address " + hex(binary_addr) + " already classified"
        n = 0
        while not is_classified(binary_addr + n) and utils.isprint(memory_binary[binary_addr + n]):
            n += 1
        assert not is_classified(binary_addr, n)

    if n > 0:
        add_classification(binary_addr, String(n))
    return movemanager.b2r(binary_addr + n)

def stringhi_binary(binary_addr, include_terminator_fn=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character.

    The string may or may not include the terminator character without
    the top bit.

    Returns the next available memory address after the string."""

    assert not is_classified(binary_addr, 1)
    initial_addr = binary_addr
    while True:
        if is_classified(binary_addr, 1):
            break
        if memory_binary[binary_addr] & 0x80 != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory_binary[binary_addr]):
                c = memory_binary[binary_addr] & 0x7f
                if utils.isprint(c) and c != ord('"') and c != ord('\''):
                    add_expression(binary_addr, "%s+'%s'" % (assembler().hex2(0x80), chr(c)))
                else:
                    add_expression(binary_addr, "%s+%s" % (assembler().hex2(0x80), assembler().hex2(c)))
                binary_addr += 1
            break
        binary_addr += 1
    if binary_addr > initial_addr:
        add_classification(initial_addr, String(binary_addr - initial_addr))
    return movemanager.b2r(binary_addr)

# Behaviour with include_terminator_fn=None should be beebdis-compatible.
def stringhiz_binary(binary_addr, include_terminator_fn=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character or zero character."""

    assert not is_classified(binary_addr, 1)
    initial_addr = binary_addr
    while True:
        if is_classified(binary_addr, 1):
            break
        if memory_binary[binary_addr] == 0 or (memory_binary[binary_addr] & 0x80) != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory_binary[binary_addr]):
                binary_addr += 1
            break
        binary_addr += 1
    if binary_addr > initial_addr:
        add_classification(initial_addr, String(binary_addr - initial_addr))
    return movemanager.b2r(binary_addr)

def stringn_binary(runtime_addr, binary_addr):
    """Classifies a part of the binary as a string with the first byte
    giving the length.

    Returns the next available memory address after the string."""

    add_classification(binary_addr, Byte(1))
    length = memory_binary[binary_addr]
    label_start = disassembly.get_label(runtime_addr + 1, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
    label_end   = disassembly.get_label(runtime_addr + 1 + length, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
    add_expression(binary_addr, utils.LazyString("%s - %s", label_end, label_start))
    add_classification(binary_addr + 1, String(length))
    return RuntimeAddr(runtime_addr + 1 + length)

def autostring(min_length=3):
    """Attempt to automatically find and classify strings through the entire binary."""

    assert min_length >= 2
    binary_addr = BinaryAddr(0)
    while binary_addr < len(memory_binary):
        i = 0
        while (binary_addr + i) < len(memory_binary) and memory_binary[binary_addr + i] is not None and not is_classified(binary_addr + i, 1) and utils.isprint(memory_binary[binary_addr + i]):
            i += 1
            runtime_addr = movemanager.b2r(binary_addr + i)

            # We end the classification here if there is a label (that is not an expression)
            if runtime_addr in labelmanager.labels:
                if not labelmanager.labels[runtime_addr].is_only_an_expression():
                    break

        # if a string is found with at least the minimum length, classify it as a string
        if i >= min_length:
            runtime_addr = movemanager.b2r(binary_addr)
            assert not is_classified(binary_addr, i)
            string_binary(binary_addr, i)
        binary_addr += max(1, i)

def include_binary_file(binary_addr, relative_filepath):
    """Add an 'include binary' command in the assembly output. The contents are
    verified to be identical to our current file contents."""
    # Add to the list of files to include
    include_binary_files[binary_addr] = relative_filepath

    # Read the binary file
    with open(relative_filepath, "rb") as fh:
        contents = fh.read()
    length = len(contents)

    # Check the contents of the file matches the file we are disassembling
    i = 0
    for b in contents:
        assert (memory_binary[binary_addr + i] == contents[i])
        i += 1

    add_classification(binary_addr, Byte(length))


def get_constant8(binary_addr):
    """Get a string representing the 8 bit constant at binary_addr.

    This could return the name of a constant, an expression or failing
    that just a constant hex value. Used by CPU Opcodes to format
    output, e.g. for converting 'LDA #3' into 'LDA #num_lives'
    """

    if binary_addr in expressions:
        return get_expression(binary_addr, memory_binary[binary_addr])
    return mainformatter.constant8(binary_addr)

def get_constant16(binary_addr):
    """Get a string representing the 16 bit constant at binary_addr.

    This could return the name of a constant, an expression or failing
    that just a constant hex value. Used by CPU Opcodes to format
    output, e.g. for converting 'LXI BC,$1234' into
    'LXI BC,my_special_constant'.
    """

    if binary_addr in expressions:
        return get_expression(binary_addr, memorymanager.get_u16_binary(binary_addr))
    return mainformatter.constant16(binary_addr)

def get_address8(binary_addr, offset=0):
    """Get a string representing the 8 bit address at binary_addr.

    This could return a label name, an expression or failing that just
    a constant hex address. Used by CPU Opcodes to format output,
    e.g. for converting 'LDA $12' into 'LDA num_lives'.
    """

    operand = (memorymanager.get_u8_binary(binary_addr) + offset) & 255
    if binary_addr not in expressions:
        return disassembly.get_label(operand, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
    return get_expression(binary_addr, operand)

def get_address16(binary_addr, offset=0):
    """Get a string representing the 16 bit address at binary_addr.

    This could return a label name, an expression or failing that just
    a constant hex address. Used by CPU Opcodes to format output, e.g.
    for converting 'JSR $1234' into 'JSR my_label'.
    """

    operand = (memorymanager.get_u16_binary(binary_addr) + offset) & 65535
    if binary_addr not in expressions or (offset != 0):
        return disassembly.get_label(operand, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)

    assert isinstance(get_classification(binary_addr), Word) or (isinstance(get_classification(binary_addr - 1), trace.cpu.Opcode) and get_classification(binary_addr - 1).length() == 3), "Address: %s" % hex(binary_addr)
    return get_expression(binary_addr, operand)


def get_stats():
    result = stats.Stats()
    binary_addr = BinaryAddr(0)
    oldc = None
    while binary_addr < len(memory_binary):
        if is_classified(binary_addr, 1):
            result.num_total_bytes += 1
            c = get_classification(binary_addr)
            if isinstance(c, Byte):
                result.num_data_bytes += 1
            elif isinstance(c, Word):
                result.num_data_words += 1
            elif isinstance(c, String):
                result.num_strings += 1
                result.num_string_bytes += 1
            elif isinstance(c, trace.cpu.Opcode):
                result.num_instructions += 1
                result.num_code_bytes += 1
            elif c == INSIDE_A_CLASSIFICATION:
                if isinstance(oldc, Byte):
                    result.num_data_bytes += 1
                elif isinstance(oldc, Word):
                    result.num_data_words += 1
                elif isinstance(oldc, String):
                    result.num_string_bytes += 1
                elif isinstance(oldc, trace.cpu.Opcode):
                    result.num_code_bytes += 1

            if c != INSIDE_A_CLASSIFICATION:
                oldc = c

        binary_addr += 1
    return result

def get_classification_map():
    result = ""
    old_c = None

    digits = "0123456789abcdef"
    result += "   "
    for i in range(0, 16):
        c = digits[i]
        result += c*16
    result += "\n   " + digits*16
    result += "\n   " + "-"*256 + "\n"

    for i in range(0, 256):
        prefix = f"{i:02x}|"
        result += prefix
        for j in range(0, 256):
            binary_addr = i*256 + j
            c = get_classification(binary_addr)
            if isinstance(c, Byte):
                result += 'B'
            elif isinstance(c, Word):
                result += 'W'
            elif isinstance(c, String):
                result += 'S'
            elif isinstance(c, trace.cpu.Opcode):
                result += 'I'
            elif c == INSIDE_A_CLASSIFICATION:
                if isinstance(oldc, Byte):
                    result += 'b'
                elif isinstance(oldc, Word):
                    result += 'w'
                elif isinstance(oldc, String):
                    result += 's'
                elif isinstance(oldc, trace.cpu.Opcode):
                    result += 'i'
            else:
                result += '.'

            if c != INSIDE_A_CLASSIFICATION:
                oldc = c
        result += "\n"
    return result

