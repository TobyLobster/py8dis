"""
Classification

Classifies every byte of a binary file.

A 'classification' says what a byte of the binary is: the start of an
instruction, or of some data bytes, words or a string. Bytes that are
loaded from a binary file are classified by type. Data is marked with a
Byte, Word or String object, and code is marked with an Opcode* object,
as defined by the configured CPU.

By the end of go() every loaded byte is classified, and the output is
made by asking each classification for its lines of output, in binary
address order (see disassembly.emit()). So the classifications decide
what the assembler is given for each byte, and between them they cover
the whole binary, so the output assembles back to the same bytes.

The classifications are kept by binary address, in
session.current().classifications.classifications (see Classifications).
Each classification object has a length, so the object is stored in the
first address of the classification, and the remainder are set to the
'INSIDE_A_CLASSIFICATION' constant so it's known to be classified. A
byte that isn't classified (yet) is None.

The kinds of classification:

Byte      some bytes of data, e.g. 'equb 1, 2, 3' (in beebasm): data
          marked by byte(), the bytes left over once everything else is
          classified (see classify_leftovers()), and an included binary
          file (see include_binary_file()).
Word      some 16 bit words of data, low byte first, e.g. a table of
          addresses, marked by word() (and wordentry() and code_ptr()).
String    a string of characters in a text encoding, e.g. 'equs "Hello"',
          marked by the string commands (below), or found by
          autostring().
Opcode    an instruction: an object from the CPU's table of opcodes (the
          Opcode class in cpu6502.py, cpu8080.py or cpuz80.py, or a
          subclass), classified by tracing (see
          cpu.Cpu.disassemble_instruction()).

They all have the same few methods:

length()            the number of bytes it covers
set_length(n)       changes that, when it's split (Byte, Word and String
                    only; see split_classification())
is_code(addr)       True for an instruction
as_lines(binary_loc, annotations)
                    its output, as a list of line objects (see output.py),
                    given its binary location (see
                    memorymanager.BinaryLocation) and the annotations (for
                    its inline comments, or None)

as_lines() is how each kind turns its bytes into output. A Byte or Word
gives an output.DataBlock, which writes the values in a table, so many to
a line; each value is a label, an expression or a formatted number, from
get_constant8() or get_constant16(). A String gives an output.StringData,
which writes the characters in quotes with the assembler's string
directive (or as bytes, if the assembler can't write the string's
encoding), over several lines if need be. An Opcode gives an
output.Instruction, whose operand comes from get_constant8(),
get_address16() etc., and a blank line after e.g. a jump (see
config.set_blank_line_at_block_end()).

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

(These commands are in commands.py. They convert the runtime address and
call the *_binary() functions here: stringterm_binary() (for stringterm(),
stringcr() and stringz()), string_binary(), stringhi_binary(),
stringhiz_binary() and stringn_binary().)

An included binary file is marked as type Byte.

This module also manages 'Expressions'. Expressions are user defined
output strings associated with an address. They are typically used for
applying some calculation or arithmetic to the immediate operands of
instructions, or to data.

e.g. An expression 'initial_lives + 1' could be used to output an
instruction 'LDA #initial_lives + 1'. The address supplied for the
expression must be of the operand, not the opcode.

Expressions are kept by binary address (add_expression()). When the
output is made, get_constant8() etc. write an operand or a data value as
its expression if it has one, and get_expression() checks the expression's
value: py8dis works it out itself where it can (see
prepare_expression_checks()), and also adds an assertion to the output for
the assembler to check (see check_expr()).
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

# (A function: assembler() is the current session's assembler)
assembler     = config.get_assembler

class Classifications:
    """The classifications (and expressions) of one session (see session.py)."""

    def __init__(self):
        # `classifications` stores classifications indexed by binary address:
        # for each of the 65536 bytes, a classification object (at its first
        # byte), INSIDE_A_CLASSIFICATION (at the rest of its bytes) or None
        # (not classified).
        self.classifications = [None] * 64*1024

        # The expression for each binary address that has one (an
        # expression.Expr, see add_expression())
        self.expressions = {}

        # Dictionary of binary files to include in the output, keyed by binary
        # address (see include_binary_file()). The Byte classification there
        # isn't output: an 'include binary' directive is, instead.
        self.include_binary_files = dict()

        # Remember the addresses where a split_classification is requested
        # (see split_classification()), so that a classification added there
        # later is split
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
    """The type of INSIDE_A_CLASSIFICATION (there's only the one)."""
    def __repr__(self):
        return "INSIDE_A_CLASSIFICATION"

INSIDE_A_CLASSIFICATION = _InsideAClassification()

class Byte:
    """Object used to mark part of the binary data as bytes.

    'length' is the number of bytes, and 'cols' the number of values on
    each line of output (None for as many as fit). 'auto_generated' is True
    for the bytes classify_leftovers() makes, which py8dis can split without
    a warning (see split_classification())."""

    def __init__(self, length, cols=None, auto_generated=False):
        assert length > 0
        assert cols is None or cols > 0
        self._length = length
        self._cols = cols
        # (True for the bytes left over once everything else is classified)
        self.auto_generated = auto_generated

    def length(self):
        """The number of bytes."""
        return self._length

    def set_length(self, length):
        """Change the number of bytes (when it's split)."""
        assert length > 0
        self._length = length

    def is_code(self, binary_addr):
        """Data isn't code."""
        return False

    def as_lines(self, binary_loc, annotations):
        """An output.DataBlock of byte values (each from get_constant8())."""
        return [output.DataBlock(binary_loc, self._length, self._cols, 1, annotations)]


class Word:
    """Object used to mark part of the binary data as words (16 bit, low
    byte first).

    'length' is in bytes, so it's twice the number of words. 'cols' is the
    number of values on each line of output (None for as many as fit)."""

    def __init__(self, length, cols=None):
        assert cols is None or cols > 0
        self.set_length(length)
        self._cols = cols

    def length(self):
        """The number of bytes (not words)."""
        return self._length

    def set_length(self, length):
        """Change the number of bytes, which must be even (when it's split)."""
        assert length > 0
        assert length % 2 == 0
        self._length = length

    def is_code(self, binary_addr):
        """Data isn't code."""
        return False

    def as_lines(self, binary_loc, annotations):
        """An output.DataBlock of word values (each from get_constant16())."""
        return [output.DataBlock(binary_loc, self._length, self._cols, 2, annotations)]


class String:
    """Object used to mark part of the binary data as a string, in the given
    text encoding (a textencoding.Encoding; by default the session's).

    'length' is the number of bytes. 'auto_generated' is True for a string
    py8dis found itself, which it can split without a warning (see
    split_classification()). '_caller' is the call stack (outside py8dis)
    where it was made, for messages (see __str__())."""

    def __init__(self, length, encoding=None):
        import textencoding
        assert length > 0
        self._length = length
        self.encoding = encoding if encoding is not None else textencoding.current()
        self._caller = utils.find_external_callstack()
        # (True for a string found by autostring())
        self.auto_generated = False

    def length(self):
        """The number of bytes."""
        return self._length

    def set_length(self, length):
        """Change the number of bytes (when it's split)."""
        assert length > 0
        self._length = length

    def is_code(self, binary_addr):
        """Data isn't code."""
        return False

    def as_lines(self, binary_loc, annotations):
        """An output.StringData, which writes the string in quotes with the
        assembler's string directive (or as bytes, if the assembler has no
        directive for its encoding), split over several lines if it's too
        long for one."""
        return [output.StringData(binary_loc, self._length, annotations, self.encoding)]

    def __str__(self):
        """A description, with the call stack where it was made, e.g. for
        add_classification()'s 'already classified' assertion."""
        #formatted_string = pprint.pformat(self._caller, indent=0)
        formatted_string = ""
        for i in self._caller:
            formatted_string = str(i) + "\n" + formatted_string
        return "String, of length {0}, during call from:\n{1}".format(self._length, formatted_string)

    def __repr__(self) -> str:
        return self.__str__()

def add_expression(binary_addr, s, *, force=True, auto_generated=True):
    """Add an expression for the given binary address.

    `s` is the expression: an expression.Expr, or anything
    expression.to_expr() makes into one (e.g. an int, a string or a
    LazyString), but not a Label.

    If `force` is False, an existing expression at the address is kept.

    An `auto_generated` expression (i.e. one py8dis makes, rather than one the
    user asks for with expr()) is not added at an address marked with
    no_automatic_comment().

    Returns the expression now at the address, or None if there isn't one
    (because an auto_generated expression wasn't added)."""

    expressions = session.current().classifications.expressions
    assert not isinstance(s, labelmanager.label_module.Label)
    s = expression.to_expr(s)
    has_existing_expr = binary_addr in expressions
    suppressed = auto_generated and (binary_addr in session.current().trace.no_auto_comment_set)
    if (force or not has_existing_expr) and not suppressed:
        expressions[binary_addr] = s

    return expressions.get(binary_addr)

def prepare_expression_checks():
    """Get ready to check expressions by evaluating them (see check_expr()).
    Called once all the labels are named, just before the output is emitted.

    This collects the value of every name an expression can use, in
    Classifications.name_values: the constants with integer values, the
    labels' names (including local labels), and the optional labels that
    are simple names (not e.g. 'irq_vector+1'). A name with more than one
    value is left out, so expressions that use it aren't evaluated. Until
    this is called, get_expression() doesn't check anything."""

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
    """Add an assert to the output based on an expression: an assertion for
    the assembler that 'expr' is 'value' (see Assembler.assert_expr()).

    If 'expr' is just a constant's name, there's no assertion (it would only
    say 'constant = value'): instead py8dis stops with an error if the
    constant's value isn't 'value' ('message' says where, e.g. "at $2001"),
    unless it's a CHAR or STRING constant, which isn't checked. ('width'
    isn't used.)

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
    of names aren't all known yet.) For an expression at the start of a
    String, the expected value is the string's text instead (e.g. for a
    STRING constant), and only the assertion checks it.

    Returns the expression, with a mask added if it needs one (see
    _evaluate_and_check()). Stops with an error if py8dis can work out its
    value and it's wrong. ('is_address' isn't used.)"""

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

    A copy of `c` is stored, so that changing it (e.g. its length, when
    it's split) doesn't change `c` itself, which may be shared: e.g. an
    opcode from the CPU's table is used for every instruction with that
    opcode.

    If a split has been asked for at an address inside it (see
    split_classification()), it's split there: each part is a copy of `c`
    with its own length. That needs set_length(), which only Byte, Word
    and String have, and a Word's parts must each be a whole number of
    words. Anything else (e.g. an instruction, or words split at an odd
    byte) is classified as bytes instead, split there, as
    split_classification() does to one that's already classified.

    It's an assertion error if any of the bytes is already classified, so
    callers check that first (see is_classified()).
    """

    split_classifications = session.current().classifications.split_classifications
    classifications = session.current().classifications.classifications
    binary_addr = BinaryAddr(binary_addr)
    assert c is not None
    assert not is_classified(binary_addr, c.length()), "Binary address {0} is already classified as {1}".format(hex(binary_addr), get_classification(binary_addr))

    splits = [i for i in range(1, c.length()) if binary_addr + i in split_classifications]
    if splits and not (hasattr(c, "set_length") and (not isinstance(c, Word) or all(i % 2 == 0 for i in splits))):
        c = Byte(c.length())

    prev_addr = binary_addr
    classifications[binary_addr] = copy.copy(c)
    for i in range(1, c.length()):
        current_addr = binary_addr+i
        if current_addr in split_classifications:
            # End the part that started at prev_addr here, and start a new
            # part, for the rest of the bytes
            classifications[prev_addr].set_length(current_addr-prev_addr)
            classifications[current_addr] = copy.copy(c)
            classifications[current_addr].set_length(c.length() - i)
            prev_addr = current_addr
        else:
            classifications[current_addr] = INSIDE_A_CLASSIFICATION

def get_classification(binary_addr):
    """The classification at a binary address: the classification object at
    the first byte of one, INSIDE_A_CLASSIFICATION at its other bytes, or
    None if the byte isn't classified."""
    classifications = session.current().classifications.classifications
    return classifications[binary_addr]

def is_classified(binary_addr, length=1):
    """Is any address in the given range classified? (The range is the
    'length' bytes from binary_addr. A byte inside a classification counts.)"""

    classifications = session.current().classifications.classifications
    return any(x is not None for x in classifications[binary_addr:binary_addr+length])

def is_code(binary_addr):
    """Is the given `binary_addr` classified as an instruction opcode? (Only
    its first byte is: this is False for the operand bytes.)"""

    classifications = session.current().classifications.classifications
    c = classifications[binary_addr]
    if c is None or c is INSIDE_A_CLASSIFICATION:
        return False
    return c.is_code(binary_addr)

def split_classification(binary_addr, *, warn):
    """If e.g. a move boundary is in the middle of an instruction, then split the classification.

    This makes binary_addr the start of a classification: for a move
    boundary (see disassembly.isolate_range()), or where the user asks with
    the split_classification() command (in commands.py).

    The address is remembered, so that a classification added across it
    later is split there (see add_classification()). If one already covers
    it, it's replaced by two Byte classifications, one before binary_addr
    and one from it, so e.g. an instruction or a string becomes bytes. With
    'warn' (for a move boundary), py8dis warns about this, unless py8dis
    made the classification itself (bytes left over, or a string found by
    autostring()). Nothing is done at the top of memory ($10000).
    """

    split_classifications = session.current().classifications.split_classifications
    classifications = session.current().classifications.classifications
    if binary_addr >= 0x10000:
        return

    # Remember the split addresses for later, so that we can avoid adding a string across the split.
    # (add_classification() splits any classification added across it.)
    split_classifications.add(binary_addr)

    if classifications[binary_addr] is not INSIDE_A_CLASSIFICATION:
        return

    # Find the start of the classification that covers it
    split_addr = binary_addr
    while classifications[binary_addr] is INSIDE_A_CLASSIFICATION:
        binary_addr -= 1

    # (Not for bytes or a string py8dis classified itself, which can be split
    # without losing anything)
    if warn and not getattr(classifications[binary_addr], "auto_generated", False):
        utils.warn("move boundary at binary address {0} splits a classification".format(config.get_assembler().hex(split_addr)))

    # classify as bytes: the part before split_addr, and the part from it
    # (whose later bytes are still marked INSIDE_A_CLASSIFICATION)
    first_split_length = split_addr - binary_addr
    classifications[split_addr] = Byte(classifications[binary_addr].length() - first_split_length)
    classifications[binary_addr] = Byte(first_split_length)

def classify_leftovers():
    """Classify everything not already classified, as bytes.

    go() calls this once tracing and the search for strings are done, so
    that every loaded byte is classified. Each run of unclassified bytes
    becomes an auto-generated Byte classification, but a run ends before
    each address with a label, so that each label starts a new
    classification."""

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
                add_classification(BinaryAddr(binary_addr), Byte(i, auto_generated=True))
            binary_addr += max(1, i)

def _is_loaded(binary_addr):
    """Is there loaded data at the binary address? (Safe at the top of memory.)"""
    memory_binary = session.current().memory.binary
    return binary_addr < len(memory_binary) and memory_binary[binary_addr] is not None

def _runtime_addr_after(binary_addr):
    """Return the runtime address for `binary_addr`, the address just after
    a string, allowing for a string that ends at the very top of memory.
    (b2r() can't convert $10000, so that's the runtime address after the
    last byte's.)"""

    memory_binary = session.current().memory.binary
    if binary_addr >= len(memory_binary):
        return movemanager.b2r(BinaryAddr(len(memory_binary) - 1)) + 1
    return movemanager.b2r(BinaryAddr(binary_addr))

def _string_error(binary_addr, message):
    """Stop with an error (utils.die()) about a string at the given binary
    address (shown as its runtime address)."""

    runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))
    utils.die("String at {0}: {1}".format(assembler().hex(runtime_addr), message))

def _check_string_start(binary_addr):
    """Check there is unclassified data at the start of a string: stop with
    an error if nothing is loaded at binary_addr, or it's already
    classified."""

    if not _is_loaded(binary_addr):
        _string_error(binary_addr, "no data is loaded there ({0})".format(memorymanager.describe_loaded_files()))
    if is_classified(binary_addr):
        _string_error(binary_addr, "it is already classified as {0}".format(describe_classification_at(binary_addr)))

def _check_string_bytes(binary_addr, length, *, report_addr=None):
    """Check `length` bytes from `binary_addr` are loaded and unclassified,
    stopping with an error if not.
    Any error is reported at `report_addr` (default `binary_addr`)."""

    if report_addr is None:
        report_addr = binary_addr
    for i in range(length):
        if not _is_loaded(binary_addr + i):
            _string_error(report_addr, "the string is {0} bytes long but the loaded data ends after {1} bytes".format(length, i))
        if is_classified(binary_addr + i):
            _string_error(report_addr, "the string is {0} bytes long but byte {1} of it is already classified as {2}".format(length, i, describe_classification_at(binary_addr + i)))

def describe_classification_at(binary_addr):
    """A short description of the classification covering the binary
    address, for messages, e.g. "byte data" or "code"."""

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

def stringterm_binary(binary_addr, terminator, exclude_terminator=False, encoding=None):
    """Classifies part of the binary as a string followed by a given
    terminator byte, for the stringterm(), stringcr() and stringz()
    commands.

    The string is in 'encoding' (by default the session's), and includes
    the terminator unless 'exclude_terminator' is set (then the terminator
    is left unclassified). Stops with an error if nothing is loaded at
    binary_addr or it's already classified, or if the loaded data ends, or
    something already classified is reached, before the terminator.

    Returns the next available memory address after the string (a runtime
    address: the one after the terminator, even if it's excluded)."""

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
        add_classification(initial_addr, String(string_length, encoding))
    return _runtime_addr_after(binary_addr + 1)

def string_binary(binary_addr, n, encoding=None):
    """Classifies part of the binary as a string of length `n`, or if `n`
    is None up to the next non-printable character (in the string's
    encoding: by default the session's) (or the end of the loaded data, or
    something already classified). For the string() command, and for
    autostring().

    Stops with an error if the start isn't loaded or is already classified,
    or, with 'n', if any of the n bytes isn't loaded or is classified.

    Returns the next available memory address after the string (a runtime
    address)."""

    import textencoding
    memory_binary = session.current().memory.binary
    if encoding is None:
        encoding = textencoding.current()
    if n is None:
        _check_string_start(binary_addr)
        n = 0
        while _is_loaded(binary_addr + n) and not is_classified(binary_addr + n) and encoding.is_printable(memory_binary[binary_addr + n]):
            n += 1
    else:
        _check_string_bytes(binary_addr, n)

    if n > 0:
        add_classification(binary_addr, String(n, encoding))
    return _runtime_addr_after(binary_addr + n)

def stringhi_binary(binary_addr, include_terminator_fn=None, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character.

    The string may or may not include the terminator character without
    the top bit. The string also ends if it reaches something already
    classified or the end of the loaded data.

    The terminator is included if include_terminator_fn(terminator) is
    True (by default it isn't, and the string ends before it). Then it's
    written as an expression for the character with bit 7 set, e.g.
    &80+'O' (see below). For the stringhi() command. Stops with an error
    if the start isn't loaded or is already classified.

    Returns the next available memory address after the string (a runtime
    address)."""

    memory_binary = session.current().memory.binary
    _check_string_start(binary_addr)
    initial_addr = binary_addr
    while True:
        if not _is_loaded(binary_addr) or is_classified(binary_addr, 1):
            break
        if memory_binary[binary_addr] & 0x80 != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory_binary[binary_addr]):
                c = memory_binary[binary_addr] & 0x7f
                # The terminator is shown as e.g. &80+'A' (in ASCII; a
                # character literal is always ASCII)
                if (encoding is None or encoding.name == "ascii") and utils.isprint(c) and c != ord('"') and c != ord('\''):
                    char = expression.Num(c, "char")
                else:
                    char = expression.Num(c, "hex2")
                add_expression(binary_addr, expression.Binary(expression.Num(0x80, "hex2"), "+", char))
                binary_addr += 1
            break
        binary_addr += 1
    if binary_addr > initial_addr:
        add_classification(initial_addr, String(binary_addr - initial_addr, encoding))
    return _runtime_addr_after(binary_addr)

# Behaviour with include_terminator_fn=None should be beebdis-compatible.
def stringhiz_binary(binary_addr, include_terminator_fn=None, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set
    character or zero character. The string also ends if it reaches
    something already classified or the end of the loaded data.

    As stringhi_binary(), for the stringhiz() command: the terminator is
    included if include_terminator_fn(terminator) is True, but it isn't
    given an expression. Returns the next available memory address after
    the string (a runtime address)."""

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
        add_classification(initial_addr, String(binary_addr - initial_addr, encoding))
    return _runtime_addr_after(binary_addr)

def stringn_binary(runtime_addr, binary_addr, encoding=None):
    """Classifies a part of the binary as a string with the first byte
    giving the length.

    For the stringn() command. The length byte is a Byte, written as an
    expression 'end - start', from labels at the start of the characters
    and just after them, and the characters (if any) are a String.
    'runtime_addr' is binary_addr's runtime address, which the labels need.
    Stops with an error if the length byte or any of the characters isn't
    loaded or is already classified.

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
        add_classification(binary_addr + 1, String(length, encoding))
    return RuntimeAddr(runtime_addr + 1 + length)

def autostring(min_length=3):
    """Attempt to automatically find and classify strings through the entire binary.

    A string is a run of at least 'min_length' bytes that aren't classified
    and are printable in the session's text encoding. A run ends before an
    address with a label (but not a label that's only an expression, e.g.
    from expr_label()). The strings found are marked auto-generated. go()
    calls this after tracing, unless the control file gives its own
    post_trace_steps."""

    import textencoding
    classifications = session.current().classifications.classifications
    memory_binary = session.current().memory.binary
    assert min_length >= 2
    # (Printable in the session's text encoding)
    printable = textencoding.current().chars

    # (For speed, this loop uses plain integer addresses.)
    memory_size = len(memory_binary)
    binary_addr = 0
    # (Only the loaded data can be classified, so just loop over that)
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = max(binary_addr, range_start)
        while binary_addr < range_end:
            i = 0
            while (binary_addr + i) < memory_size and memory_binary[binary_addr + i] is not None and classifications[binary_addr + i] is None and memory_binary[binary_addr + i] in printable:
                i += 1
                if binary_addr + i >= memory_size:
                    # (The top of memory)
                    break
                runtime_addr = movemanager.b2r(BinaryAddr(binary_addr + i))

                # We end the classification here if there is a label (that is not an expression)
                if runtime_addr in session.current().labels.labels:
                    if not session.current().labels.labels[runtime_addr].is_only_an_expression():
                        break

            # if a string is found with at least the minimum length, classify it as a string
            if i >= min_length:
                assert not is_classified(binary_addr, i)
                string_binary(BinaryAddr(binary_addr), i)
                classifications[binary_addr].auto_generated = True
            binary_addr += max(1, i)

def include_binary_file(binary_addr, relative_filepath):
    """Add an 'include binary' command in the assembly output. The contents are
    verified to be identical to our current file contents.

    For the include_binary_file() command: the bytes at binary_addr are
    written as a directive to include 'relative_filepath' (e.g. beebasm's
    incbin), rather than as data. They're classified as a single Byte,
    whose lines disassembly.emit() replaces with the directive (see
    Classifications.include_binary_files). Stops with an error if the file
    can't be read, is empty, runs past the top of memory, doesn't match the
    loaded data, or some of it is already classified."""
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
            die("no data is loaded at {0} (offset {1} in the file; {2})".format(h(binary_addr + i), i, memorymanager.describe_loaded_files()))
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

    (It's the expression given for the address, if there is one (see
    get_expression()); otherwise the number, formatted as asked for, e.g.
    by decimal() (see mainformatter.constant8()). Data uses it too, for
    each byte of a Byte classification.)
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

    (As get_constant8(), for the 16 bit number, low byte first; data uses
    it for each word of a Word classification.)
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

    (It's the expression given for the address, if there is one;
    otherwise the label for the address (see disassembly.get_label()).
    'offset' is added to the byte first, wrapping round within 8 bits.)
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

    (As get_address8(), for the 16 bit address, low byte first, with
    'offset' added, wrapping round within 16 bits. With an 'offset' other
    than 0, any expression for the address is ignored. An expression must
    be at a Word, or at the address in an instruction, its last two bytes
    (e.g. a 6502 'lda $1234', or a Z80 'ld ix,($1234)', which has a prefix
    byte too): it's an assertion error otherwise.)
    """

    expressions = session.current().classifications.expressions
    operand = (memorymanager.get_u16_binary(binary_addr) + offset) & 65535
    if binary_addr not in expressions or (offset != 0):
        return disassembly.get_label(operand, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)

    def is_instruction_address(binary_addr):
        """True if binary_addr is the address in an instruction: its last two
        bytes, after one to three bytes of opcode (and prefix)."""
        for opcode_length in (1, 2, 3):
            c = get_classification(binary_addr - opcode_length)
            if c is not INSIDE_A_CLASSIFICATION:
                return isinstance(c, session.current().cpu.Opcode) and c.length() == opcode_length + 2
        return False

    assert isinstance(get_classification(binary_addr), Word) or is_instruction_address(binary_addr), "Address: %s" % hex(binary_addr)
    return get_expression(binary_addr, operand, is_address=True, width=16)


def get_stats():
    """How many bytes are classified as each kind (a stats.Stats), for the
    statistics at the end of the output (see config.set_show_stats()).

    Each byte is counted (by the kind of the classification it's in), so
    'num_data_words' is a number of bytes too. 'num_instructions' and
    'num_strings' count the classifications themselves."""
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
                # (A later byte of the classification 'oldc' started)
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
    """A text map of how each byte of memory is classified, for debugging.

    After the headings (two lines giving the low byte of each column's
    address, one hex digit above the other, then a line of dashes), there's
    a line for each page of memory (e.g. '20|' for $2000-$20ff), with a
    character for each byte: a capital letter for the first byte of
    a classification ('B' bytes, 'W' words, 'S' a string, 'I' an
    instruction), the small letter for the rest of its bytes, and '.' for a
    byte that isn't classified."""
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

