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

import collections
import config
import copy
import disassembly
import expression
import labelmanager
import mainformatter
import memorymanager
import movemanager
import output
import session
import pprint
import stats
import trace
import traceback
import utils
from memorymanager import BinaryAddr, RuntimeAddr
from format import Format
from binaryaddrtype import BinaryAddrType

assembler     = config.get_assembler

class Classifications:
    """The classifications (and expressions) of one session (see session.py)."""

    def __init__(self):
        # `classifications` stores classifications indexed by binary address.
        self.classifications = [None] * 64*1024

        # The expression for each binary address that has one
        self.expressions = {}

        # Dictionary of binary files to include in the output, keyed by binary address
        self.include_binary_files = dict()

        # Remember the addresses where a split_classification is requested
        self.split_classifications = set()

        # The values of names (constants and labels), for evaluating
        # expressions. This is set up by prepare_expression_checks() once all
        # the labels are named.
        self.name_values = None

# `INSIDE_A_CLASSIFICATION` is a unique marker object.
#
# We assign this value to the second and subsequent bytes of a multi-byte
# classification (e.g. the operands of an instruction), so we know these bytes
# have been classified. Compare with it using 'is'. (Being a unique object, it
# can't be confused with 0, False or None.)
class _InsideAClassification:
    def __repr__(self):
        return "INSIDE_A_CLASSIFICATION"

INSIDE_A_CLASSIFICATION = _InsideAClassification()

# ENHANCE: At the moment there's no support for wrapping round at the top of
# memory and we might just crash (probably with an out-of-bounds error) if
# disassembling right up to the top of memory.

class Byte:
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

    def as_lines(self, binary_loc, annotations):
        return [output.DataBlock(binary_loc, self._length, self._cols, 1, annotations)]


class Word:
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

    def as_lines(self, binary_loc, annotations):
        return [output.DataBlock(binary_loc, self._length, self._cols, 2, annotations)]


class String:
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

    def as_lines(self, binary_loc, annotations):
        return [output.StringData(binary_loc, self._length, annotations)]

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

def add_expression(binary_addr, s, *, force=True, auto_generated=True):
    """Add an expression for the given binary address.

    If `force` is False, an existing expression at the address is kept.

    An `auto_generated` expression (i.e. one py8dis makes, rather than one the
    user asks for with expr()) is not added at an address marked with
    no_automatic_comment().

    Returns the expression now at the address, or None if there isn't one
    (because an auto_generated expression wasn't added)."""

    expressions = session.current().classifications.expressions
    assert not isinstance(s, labelmanager.label_module.Label) # TODO!?
    s = expression.to_expr(s)
    # TODO: Warn/assert if binary_addr already in expressions? Allow overriding this via an optional bool argument?
    has_existing_expr = binary_addr in expressions
    suppressed = auto_generated and (binary_addr in session.current().trace.no_auto_comment_set)
    if (force or not has_existing_expr) and not suppressed:
        expressions[binary_addr] = s

    return expressions.get(binary_addr)

def prepare_expression_checks():
    """Get ready to check expressions by evaluating them (see check_expr()).
    Called once all the labels are named, just before the output is emitted."""

    values = {}
    ambiguous = set()
    def add(name, value):
        if name in values and values[name] != value:
            ambiguous.add(name)
        values[name] = value

    for c in session.current().disassembly.constants:
        if utils.is_integer_type(c.value):
            add(c.name, c.value)
    for runtime_addr, label in session.current().labels.labels.items():
        for name_list in label.explicit_names.values():
            for name in name_list:
                add(name.text, int(runtime_addr))
        for local_labels in label.local_labels.values():
            for local_label in local_labels:
                add(local_label.output_name, int(runtime_addr))
    for runtime_addr, optional_label in session.current().disassembly.optional_labels.items():
        if optional_label.base_address is None:
            add(optional_label.name, int(runtime_addr))

    # A name with more than one value can't be used to evaluate an expression
    for name in ambiguous:
        del values[name]
    session.current().classifications.name_values = values

def check_expr(expr, value, message, width=None):
    """Add an assert to the output based on an expression.

    (py8dis also checks the value itself where it can, see
    _evaluate_and_check(). The assertions are kept as well, since the
    assembler can check every expression, including the ones py8dis can't
    evaluate, e.g. expression strings written by the user.)"""

    # Don't clutter the output with pedantic 'constant = value' assertions
    for constant in session.current().disassembly.constants:
        if expr == constant.name:
            if constant.format == Format.CHAR:
                return
            elif constant.format == Format.STRING:
                return
            elif (constant.value != value):
                utils.die("Constant '{0}' found to be {1} but expected to be {2} {3}".format(expr, constant.value, value, message))
            return

    config.get_assembler().assert_expr(expr, value)

def _evaluate_and_check(binary_addr, expr, expected_value, width):
    """Check an expression's value, if py8dis can work it out (i.e. it doesn't
    use an expression string written by the user, or an unknown name).

    Stops with an error if the value is wrong. If the value is right except
    that it's outside the range of a 'width' bit number (e.g. NOT gives a
    negative number), returns the expression with a mask added (e.g.
    'expr AND $ff'). Otherwise returns the expression unchanged."""

    value = expression.evaluate(expr, session.current().classifications.name_values.get)
    if value is None or value == expected_value:
        return expr

    mask = (1 << width) - 1
    if (value & mask) == expected_value:
        # Right, apart from the range
        return expression.Binary(expr, 'AND', expression.Num(mask, "hex"))

    h = assembler().hex
    def show(v):
        return h(v) if 0 <= v <= 0xffff else str(v)
    utils.die("expr() at {0}: '{1}' is {2}, but the {3} there is {4}".format(
        h(movemanager.b2r(binary_addr)), expr, show(value), "byte" if width == 8 else "word", h(expected_value)))

def get_expression(binary_addr, expected_value, is_address=False, width=8):
    """Get the previously supplied expression for the given address, whose
    value should be 'expected_value', a 'width' bit number.

    Once the output is being made (see prepare_expression_checks()), the
    expression is also checked, and an assertion added to the output. (Before
    then, e.g. when label names are being chosen, it isn't, since the values
    of names aren't all known yet.)"""

    expressions = session.current().classifications.expressions
    memory_binary = session.current().memory.binary
    expr = expressions[binary_addr]
    if session.current().classifications.name_values is None:
        return expr

    c = get_classification(binary_addr)
    if isinstance(c, String):
        expected_value = "".join(chr(memory_binary[binary_addr + i]) for i in range(c.length()))
    else:
        expr = _evaluate_and_check(binary_addr, expr, expected_value, width)
    check_expr(expr, expected_value, "at {0}".format(assembler().hex(movemanager.b2r(binary_addr))), width)

    return expr

def add_classification(binary_addr, c):
    """Sets the classification for the given address.

    A classification has a length in bytes. The first byte is
    classified with the given classification and all following bytes
    are marked with `INSIDE_A_CLASSIFICATION`.
    """

    split_classifications = session.current().classifications.split_classifications
    classifications = session.current().classifications.classifications
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
    classifications = session.current().classifications.classifications
    return classifications[binary_addr]

def is_classified(binary_addr, length=1):
    """Is any address in the given range classified?"""

    classifications = session.current().classifications.classifications
    return any(x is not None for x in classifications[binary_addr:binary_addr+length])

def is_code(binary_addr):
    """Is the given `binary_addr` classified as an instruction opcode?"""

    classifications = session.current().classifications.classifications
    c = classifications[binary_addr]
    if c is None or c is INSIDE_A_CLASSIFICATION:
        return False
    return c.is_code(binary_addr)

def split_classification(binary_addr, *, warn):
    """If e.g. a move boundary is in the middle of an instruction, then split the classification."""

    split_classifications = session.current().classifications.split_classifications
    classifications = session.current().classifications.classifications
    if binary_addr >= 0x10000:
        return

    # Remember the split addresses for later, so that we can avoid adding a string across the split.
    split_classifications.add(binary_addr)

    if classifications[binary_addr] is not INSIDE_A_CLASSIFICATION:
        return

    # TODO: Do we need to check and not warn if this is just an automatic string/byte classification?
    if warn:
        utils.warn("move boundary at binary address {0} splits a classification".format(config.get_assembler().hex(binary_addr)))
    split_addr = binary_addr
    while classifications[binary_addr] is INSIDE_A_CLASSIFICATION:
        binary_addr -= 1

    # classify as bytes
    first_split_length = split_addr - binary_addr
    classifications[split_addr] = Byte(classifications[binary_addr].length() - first_split_length)
    classifications[binary_addr] = Byte(first_split_length)

def classify_leftovers():
    """Classify everything not already classified, as bytes."""

    # (For speed, this loop uses plain integer addresses.)
    classifications = session.current().classifications.classifications
    memory_binary = session.current().memory.binary
    memory_size = len(memory_binary)
    binary_addr = 0
    labels = session.current().labels.labels
    # (Only the loaded data can be classified, so just loop over that)
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = max(binary_addr, range_start)
        while binary_addr < range_end:
            i = 0
            while (binary_addr + i) < memory_size and memory_binary[binary_addr + i] is not None and classifications[binary_addr + i] is None:
                i += 1
                if (binary_addr + i) >= memory_size or movemanager.b2r(BinaryAddr(binary_addr + i)) in labels:
                    break
            if i > 0:
                add_classification(BinaryAddr(binary_addr), Byte(i))
            binary_addr += max(1, i)

def _is_loaded(binary_addr):
    """Is there loaded data at the binary address? (Safe at the top of memory.)"""
    memory_binary = session.current().memory.binary
    return binary_addr < len(memory_binary) and memory_binary[binary_addr] is not None

def _runtime_addr_after(binary_addr):
    """Return the runtime address for `binary_addr`, the address just after
    a string, allowing for a string that ends at the very top of memory."""

    memory_binary = session.current().memory.binary
    if binary_addr >= len(memory_binary):
        return movemanager.b2r(BinaryAddr(len(memory_binary) - 1)) + 1
    return movemanager.b2r(BinaryAddr(binary_addr))

def _string_error(binary_addr, message):
    """Stop with an error about a string at the given binary address."""

    runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))
    utils.die("String at {0}: {1}".format(assembler().hex(runtime_addr), message))

def _check_string_start(binary_addr):
    """Check there is unclassified data at the start of a string."""

    if not _is_loaded(binary_addr):
        _string_error(binary_addr, "no data is loaded there")
    if is_classified(binary_addr):
        _string_error(binary_addr, "it is already classified as {0}".format(describe_classification_at(binary_addr)))

def _check_string_bytes(binary_addr, length, *, report_addr=None):
    """Check `length` bytes from `binary_addr` are loaded and unclassified.
    Any error is reported at `report_addr` (default `binary_addr`)."""

    if report_addr is None:
        report_addr = binary_addr
    for i in range(length):
        if not _is_loaded(binary_addr + i):
            _string_error(report_addr, "the string is {0} bytes long but the loaded data ends after {1} bytes".format(length, i))
        if is_classified(binary_addr + i):
            _string_error(report_addr, "the string is {0} bytes long but byte {1} of it is already classified as {2}".format(length, i, describe_classification_at(binary_addr + i)))

def describe_classification_at(binary_addr):
    """A short description of the classification covering the binary address, for messages."""

    classifications = session.current().classifications.classifications
    while classifications[binary_addr] is INSIDE_A_CLASSIFICATION and binary_addr > 0:
        binary_addr -= 1
    c = classifications[binary_addr]
    if isinstance(c, Byte):
        return "byte data"
    if isinstance(c, Word):
        return "word data"
    if isinstance(c, String):
        return "a string"
    if session.current().cpu is not None and isinstance(c, session.current().cpu.Opcode):
        return "code"
    return "something else"

def stringterm_binary(binary_addr, terminator, exclude_terminator=False):
    """Classifies part of the binary as a string followed by a given
    terminator byte.

    Returns the next available memory address after the string."""

    memory_binary = session.current().memory.binary
    _check_string_start(binary_addr)
    initial_addr = binary_addr
    while True:
        if not _is_loaded(binary_addr):
            _string_error(initial_addr, "no terminator ({0}) found before the end of the loaded data".format(assembler().hex2(terminator)))
        is_terminator = (memory_binary[binary_addr] == terminator)
        is_part_of_string = not (is_terminator and exclude_terminator)
        if is_part_of_string and is_classified(binary_addr):
            _string_error(initial_addr, "no terminator ({0}) found before reaching {1}, which is already classified as {2}".format(
                assembler().hex2(terminator), assembler().hex(movemanager.b2r(binary_addr)), describe_classification_at(binary_addr)))
        if is_terminator:
            break
        binary_addr += 1
    string_length = (binary_addr + 1) - initial_addr
    if exclude_terminator:
        string_length -= 1
    if string_length > 0:
        add_classification(initial_addr, String(string_length))
    return _runtime_addr_after(binary_addr + 1)

def string_binary(binary_addr, n):
    """Classifies part of the binary as a string of length `n`, or if `n`
    is None up to the next non-printable character (or the end of the
    loaded data, or something already classified).

    Returns the next available memory address after the string."""

    memory_binary = session.current().memory.binary
    if n is None:
        _check_string_start(binary_addr)
        n = 0
        while _is_loaded(binary_addr + n) and not is_classified(binary_addr + n) and utils.isprint(memory_binary[binary_addr + n]):
            n += 1
    else:
        _check_string_bytes(binary_addr, n)

    if n > 0:
        add_classification(binary_addr, String(n))
    return _runtime_addr_after(binary_addr + n)

def stringhi_binary(binary_addr, include_terminator_fn=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character.

    The string may or may not include the terminator character without
    the top bit. The string also ends if it reaches something already
    classified or the end of the loaded data.

    Returns the next available memory address after the string."""

    memory_binary = session.current().memory.binary
    _check_string_start(binary_addr)
    initial_addr = binary_addr
    while True:
        if not _is_loaded(binary_addr) or is_classified(binary_addr, 1):
            break
        if memory_binary[binary_addr] & 0x80 != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory_binary[binary_addr]):
                c = memory_binary[binary_addr] & 0x7f
                # The terminator is shown as e.g. &80+'A'
                if utils.isprint(c) and c != ord('"') and c != ord('\''):
                    char = expression.Num(c, "char")
                else:
                    char = expression.Num(c, "hex2")
                add_expression(binary_addr, expression.Binary(expression.Num(0x80, "hex2"), "+", char))
                binary_addr += 1
            break
        binary_addr += 1
    if binary_addr > initial_addr:
        add_classification(initial_addr, String(binary_addr - initial_addr))
    return _runtime_addr_after(binary_addr)

# Behaviour with include_terminator_fn=None should be beebdis-compatible.
def stringhiz_binary(binary_addr, include_terminator_fn=None):
    """Classifies a part of the binary as a string up to the next bit 7 set
    character or zero character. The string also ends if it reaches
    something already classified or the end of the loaded data."""

    memory_binary = session.current().memory.binary
    _check_string_start(binary_addr)
    initial_addr = binary_addr
    while True:
        if not _is_loaded(binary_addr) or is_classified(binary_addr, 1):
            break
        if memory_binary[binary_addr] == 0 or (memory_binary[binary_addr] & 0x80) != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory_binary[binary_addr]):
                binary_addr += 1
            break
        binary_addr += 1
    if binary_addr > initial_addr:
        add_classification(initial_addr, String(binary_addr - initial_addr))
    return _runtime_addr_after(binary_addr)

def stringn_binary(runtime_addr, binary_addr):
    """Classifies a part of the binary as a string with the first byte
    giving the length.

    Returns the next available memory address after the string."""

    memory_binary = session.current().memory.binary
    _check_string_start(binary_addr)
    length = memory_binary[binary_addr]
    _check_string_bytes(binary_addr + 1, length, report_addr=binary_addr)

    add_classification(binary_addr, Byte(1))
    label_start = disassembly.get_label(runtime_addr + 1, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
    label_end   = disassembly.get_label(runtime_addr + 1 + length, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)
    add_expression(binary_addr, expression.Binary(expression.to_expr(label_end), "-", expression.to_expr(label_start)))
    if length > 0:
        add_classification(binary_addr + 1, String(length))
    return RuntimeAddr(runtime_addr + 1 + length)

def autostring(min_length=3):
    """Attempt to automatically find and classify strings through the entire binary."""

    classifications = session.current().classifications.classifications
    memory_binary = session.current().memory.binary
    assert min_length >= 2

    # (For speed, this loop uses plain integer addresses.)
    memory_size = len(memory_binary)
    binary_addr = 0
    # (Only the loaded data can be classified, so just loop over that)
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = max(binary_addr, range_start)
        while binary_addr < range_end:
            i = 0
            while (binary_addr + i) < memory_size and memory_binary[binary_addr + i] is not None and classifications[binary_addr + i] is None and utils.isprint(memory_binary[binary_addr + i]):
                i += 1
                runtime_addr = movemanager.b2r(BinaryAddr(binary_addr + i))

                # We end the classification here if there is a label (that is not an expression)
                if runtime_addr in session.current().labels.labels:
                    if not session.current().labels.labels[runtime_addr].is_only_an_expression():
                        break

            # if a string is found with at least the minimum length, classify it as a string
            if i >= min_length:
                assert not is_classified(binary_addr, i)
                string_binary(BinaryAddr(binary_addr), i)
            binary_addr += max(1, i)

def include_binary_file(binary_addr, relative_filepath):
    """Add an 'include binary' command in the assembly output. The contents are
    verified to be identical to our current file contents."""
    include_binary_files = session.current().classifications.include_binary_files
    memory_binary = session.current().memory.binary
    h = config.get_assembler().hex
    def die(problem):
        utils.die("include_binary_file({0}, {1!r}): {2}".format(h(binary_addr), relative_filepath, problem))

    # Add to the list of files to include
    include_binary_files[binary_addr] = relative_filepath

    # Read the binary file
    try:
        with open(relative_filepath, "rb") as fh:
            contents = fh.read()
    except OSError as e:
        die("can't read the file ({0})".format(e.strerror))
    length = len(contents)
    if length == 0:
        die("the file is empty")
    if binary_addr + length > 0x10000:
        die("the file ({0} bytes) runs past the top of memory".format(length))

    # Check the contents of the file matches the file we are disassembling
    for i in range(length):
        if memory_binary[binary_addr + i] is None:
            die("no data is loaded at {0} (offset {1} in the file)".format(h(binary_addr + i), i))
        if memory_binary[binary_addr + i] != contents[i]:
            die("the file doesn't match the loaded data at {0} (offset {1} in the file)".format(h(binary_addr + i), i))
    if is_classified(binary_addr, length):
        die("some of this data has already been classified (e.g. by an earlier byte(), word() or string command)")

    add_classification(binary_addr, Byte(length))


def get_constant8(binary_addr):
    """Get a string representing the 8 bit constant at binary_addr.

    This could return the name of a constant, an expression or failing
    that just a constant hex value. Used by CPU Opcodes to format
    output, e.g. for converting 'LDA #3' into 'LDA #num_lives'
    """

    expressions = session.current().classifications.expressions
    memory_binary = session.current().memory.binary
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

    expressions = session.current().classifications.expressions
    if binary_addr in expressions:
        return get_expression(binary_addr, memorymanager.get_u16_binary(binary_addr), width=16)
    return mainformatter.constant16(binary_addr)

def get_address8(binary_addr, offset=0):
    """Get a string representing the 8 bit address at binary_addr.

    This could return a label name, an expression or failing that just
    a constant hex address. Used by CPU Opcodes to format output,
    e.g. for converting 'LDA $12' into 'LDA num_lives'.
    """

    expressions = session.current().classifications.expressions
    operand = (memorymanager.get_u8_binary(binary_addr) + offset) & 255
    if binary_addr not in expressions:
        return disassembly.get_label(operand, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
    return get_expression(binary_addr, operand, is_address=True)

def get_address16(binary_addr, offset=0):
    """Get a string representing the 16 bit address at binary_addr.

    This could return a label name, an expression or failing that just
    a constant hex address. Used by CPU Opcodes to format output, e.g.
    for converting 'JSR $1234' into 'JSR my_label'.
    """

    expressions = session.current().classifications.expressions
    operand = (memorymanager.get_u16_binary(binary_addr) + offset) & 65535
    if binary_addr not in expressions or (offset != 0):
        return disassembly.get_label(operand, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)

    assert isinstance(get_classification(binary_addr), Word) or (isinstance(get_classification(binary_addr - 1), session.current().cpu.Opcode) and get_classification(binary_addr - 1).length() == 3), "Address: %s" % hex(binary_addr)
    return get_expression(binary_addr, operand, is_address=True, width=16)


def get_stats():
    classifications = session.current().classifications.classifications
    memory_binary = session.current().memory.binary
    result = stats.Stats()
    oldc = None
    # (For speed, this loop uses plain integer addresses.)
    for binary_addr in range(len(memory_binary)):
        c = classifications[binary_addr]
        if c is not None:
            result.num_total_bytes += 1
            if isinstance(c, Byte):
                result.num_data_bytes += 1
            elif isinstance(c, Word):
                result.num_data_words += 1
            elif isinstance(c, String):
                result.num_strings += 1
                result.num_string_bytes += 1
            elif isinstance(c, session.current().cpu.Opcode):
                result.num_instructions += 1
                result.num_code_bytes += 1
            elif c is INSIDE_A_CLASSIFICATION:
                if isinstance(oldc, Byte):
                    result.num_data_bytes += 1
                elif isinstance(oldc, Word):
                    result.num_data_words += 1
                elif isinstance(oldc, String):
                    result.num_string_bytes += 1
                elif isinstance(oldc, session.current().cpu.Opcode):
                    result.num_code_bytes += 1

            if c is not INSIDE_A_CLASSIFICATION:
                oldc = c

    return result

def get_classification_map():
    result = ""
    oldc = None

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
            elif isinstance(c, session.current().cpu.Opcode):
                result += 'I'
            elif c is INSIDE_A_CLASSIFICATION:
                if isinstance(oldc, Byte):
                    result += 'b'
                elif isinstance(oldc, Word):
                    result += 'w'
                elif isinstance(oldc, String):
                    result += 's'
                elif isinstance(oldc, session.current().cpu.Opcode):
                    result += 'i'
            else:
                result += '.'

            if c is not INSIDE_A_CLASSIFICATION:
                oldc = c
        result += "\n"
    return result

