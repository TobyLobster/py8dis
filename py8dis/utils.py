"""
Utility functions

Small helpers used all through py8dis:

- reporting problems: die() for an error (e.g. a mistake in the control
  file), which stops py8dis, warn() for a warning, and debug();
- text: force_case(), plainhex2() and plainhex4() write in the case chosen
  with config.set_lower_case(); tab_to() and make_indent() lay out lines;
  and_list(), count_with_units() and format_strings_in_a_table() make text
  for comments and data;
- numbers and types: signed8(), round_up(), is_integer_type() etc.;
- LazyString, text that isn't worked out until the output is made (e.g. a
  comment containing a label, whose name isn't chosen until after tracing);
- keydefaultdict, a defaultdict that passes the key to its factory;
- sorted_annotations(), the order the annotations (comments etc.) at an
  address are output in;
- the call stack (get_callstack(), find_external_callstack()), used to say
  which line of a control file made something, for debugging.

Of py8dis's own modules, this one uses only config (for the case of the
output and the indent); almost every other module uses this one.
"""

import collections
import linecache
import os
import re
import sys
import traceback

import config

# The folder py8dis's own code is in (see find_external_callstack())
library_path = os.path.dirname(os.path.abspath(__file__))

def die(s):
    """Print the error message s (to stderr) and stop, with exit status 1.

    This is how py8dis reports a problem with the control file or the
    program being disassembled, so the user sees just the message, not a
    traceback. (Checks of the user's input use this rather than 'assert',
    which 'python -O' removes.)"""

    # Alternative: Raise exception (which reports the callstack too)
    #raise ValueError(s)

    # Print error message
    print(s, file=sys.stderr)
    sys.exit(1)

def warn(s):
    """Print a warning message, 'warning: ...' (to stderr), and carry on."""
    print("warning: %s" % (s), file=sys.stderr)

def and_list(items):
    """The items (strings) as English: 'a', 'a and b', or 'a, b and c'."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]

def debug(s):
    """Print a debug message, 'debug: ...' (to stderr), and carry on. For
    debugging py8dis itself."""
    print("debug: %s" % (s), file=sys.stderr)

def force_case(s):
    """The string s in lower or upper case, as set by
    config.set_lower_case(): used for mnemonics, directives, register names
    and py8dis's own labels (e.g. 'l1234')."""

    return s.lower() if config.get_lower_case() else s.upper()

def plainhex2(i):
    """i as two hex digits, with no prefix, in the case of the output, e.g.
    '1f'. (An assembler's hex2() adds its prefix, e.g. '&1f' or '$1f'.)"""

    return ("%02x" if config.get_lower_case() else "%02X") % i

def plainhex4(i):
    """i as four hex digits, with no prefix, in the case of the output, e.g.
    '201f'."""

    return ("%04x" if config.get_lower_case() else "%04X") % i

def tab_to(s, n):
    """s padded with spaces on the right to n characters, to line up the
    next thing in column n. (s is left as it is if it's already that long.)"""

    assert n >= 0
    return "%-*s" % (n, s)

def make_indent(n):
    """n levels of indent: n copies of the indent string (see
    config.set_indent_string())."""

    assert n >= 0
    return (config.get_indent_string()) * n

def signed8(i):
    """The byte i (0 to 255) as a signed number (-128 to 127), e.g. for a
    branch's offset."""

    assert 0 <= i <= 255
    if i >= 0x80:
        return i - 256
    else:
        return i

# https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
def chunks(lst, n):
    """Yield successive n-sized chunks from lst (the last may be shorter)."""

    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def isprint(c):
    """Is the byte value c a printable ASCII character (space to '~')? (This
    is ASCII only: for a string's own text encoding, see
    textencoding.Encoding.is_printable().)"""

    return 32 <= c <= 126

def count_with_units(n, unit_name_singular, unit_name_plural):
    """Describes a count of a given unit e.g. "3 apples".

    Returns a string with the amount given and the unit name either
    in singular or plural form. 'n' can be a number, or text, which takes
    the plural unless it's "1".
    """
    if is_string_type(n) and (n == "1"):
        n = 1
    if is_integer_type(n):
        return "%d %s" % (n, unit_name_singular if n == 1 else unit_name_plural)
    else:
        return "%s %s" % (n, unit_name_plural)

def is_string_type(item):
    """Is item a string?"""
    return isinstance(item, str)

def is_integer_type(item):
    """Is item an integer? (This includes BinaryAddr and RuntimeAddr, which
    are ints, and also True and False, since bool is a kind of int.)"""
    return isinstance(item, int)

def is_integer_string(s):
    """Does the text s look like a whole number: digits, optionally with a
    sign and a '$' or '&' hex prefix, e.g. '12', '-$1f' or '&ff'?

    Bare hex digits match too, so e.g. 'ff', and words such as 'add' or
    'dead', do. That's harmless for its use in expression._text_level(),
    where it decides that text needn't be bracketed, since a simple name
    needn't be either."""
    assert s is not None
    if s is None:
        return False
    if re.fullmatch(r'[+-]?[$&]?[0-9A-Fa-f]+', s):
        return True
    return False

# See https://stackoverflow.com/a/11150413
def natural_sort(l):
    """The strings in l, sorted in 'natural' order: runs of digits compare
    as numbers, and the rest without regard to case, so e.g. 'l2' comes
    before 'l10'. (disassembly.sorted_constants() sorts the same way.)"""
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
    return sorted(l, key=alphanum_key)

class LazyString:
    """Text made of parts, some of which aren't known until the output is
    made: e.g. 'Copy 8 bytes from ' + a label, whose name is only chosen
    after tracing. The text is 'fmt % args', worked out (once) when it's
    first converted to a string.

    The parts are kept, so the labels in it can be found (see
    output.label_refs()). A label reference (disassembly.LabelRef) is a
    LazyString too, so a label can be joined to text either way round.

    (An argument can also be a function to call, for compatibility with
    control files that use this. py8dis itself doesn't.)"""

    def __init__(self, fmt, *args):
        self._fmt = fmt
        self._args = args
        self.resolved = None

    def __str__(self):
        if self.resolved is None:
            self.resolved = self._fmt % tuple(x() if callable(x) else x for x in self._args)
        return self.resolved

    def __add__(self, other):
        """A new LazyString of this text followed by 'other' (still not
        worked out), e.g. get_label(...) + " table"."""
        if isinstance(other, LazyString):
            return LazyString(self._fmt + other._fmt, *(self._args + other._args))
        return LazyString(self._fmt + "%s", *(list(self._args) + [other]))

    def __radd__(self, other):
        """A new LazyString of 'other' followed by this text."""
        # e.g. "jump to " + get_label(...)
        return LazyString("%s" + self._fmt, *([other] + list(self._args)))

    def __len__(self):
        """The length of the text. This works the text out (and keeps it), so
        it mustn't be used until the labels in it can be named."""
        return len(str(self))

# https://stackoverflow.com/questions/2912231/is-there-a-clever-way-to-pass-the-key-to-defaultdicts-default-factory
class keydefaultdict(collections.defaultdict):
    """A defaultdict whose default_factory is given the missing key, e.g.
    labelmanager.Labels.labels, where looking up a new runtime address makes
    a Label for that address."""

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError( key )
        else:
            ret = self[key] = self.default_factory(key)
            return ret

def remove_consecutive_duplicates(binary_loc, annotations):
    """The annotations (comments etc., see comment.py), without each
    auto-generated one whose text, as output at binary_loc, is the same as
    the one kept before it. This stops py8dis repeating a comment it has
    added twice. The user's own annotations are always kept, and the order
    is unchanged."""
    if not annotations:
        return []

    # Initialize the result list with the first object
    result = [annotations[0]]

    # Remove duplicate annotations if they are auto_generated
    for i in range(1, len(annotations)):
        # Compare the string representation of the current object with the last one in the result list
        if not annotations[i].auto_generated:
            result.append(annotations[i])
        elif annotations[i].as_string(binary_loc.binary_addr) != result[-1].as_string(binary_loc.binary_addr):
            result.append(annotations[i])

    return result

def sorted_annotations(binary_loc, annotations):
    """The annotations at binary_loc in the order they're output: by where
    they go (their align.Align value, e.g. BEFORE_LABEL before INLINE), then
    by priority, then in the order they were added (the sort is stable),
    without repeated auto-generated ones (see
    remove_consecutive_duplicates())."""
    result = remove_consecutive_duplicates(binary_loc, sorted(annotations, key=lambda x: (x.align, x.priority)))
    return result

def round_up(n: int, multiple: int = 4) -> int:
    """
    Rounds up an integer to the next multiple of the specified number.

    Args:
        n (int): The input integer to round up
        multiple (int): The multiple to round up to (default: 4)

    Returns:
        int: The next multiple of the specified number greater than or equal to the input

    Examples:
        >>> round_up(5)  # default multiple of 4
        8
        >>> round_up(5, multiple=3)
        6
        >>> round_up(7, multiple=5)
        10
        >>> round_up(10, multiple=2)
        10
    """
    return ((n + (multiple - 1)) // multiple) * multiple

def format_strings_in_a_table(strings, max_width, items_per_line_already_known, formatter_for_line, right_align=True):
    """
    Format a list of strings into lines with equal number of items per line.
    Entries are comma separated. Entries are aligned vertically by padding
    with spaces. This lays out the values of a block of data (e.g. the
    bytes after an 'equb', see output.py), as many to a line as fit, in
    columns.

    Just before each line is added to the result, a formatter is called:
        formatter_for_line(line, start_index, end_index)
    to get the final text for the line.

    Args:
        strings (list): List of strings to format
        max_width (int): Maximum width of each line
        items_per_line_already_known (int or None): the number of items per
            line to use (e.g. the 'cols' given to byte()), however wide the
            lines are; or None (or 0) for the most that fit in max_width
            (at least one)
        formatter_for_line (function): called as above for each line, with
            the line's text and the indexes of its first item and of the
            item after its last; returns the final text for the line (e.g.
            with the directive and hex dump added)
        right_align (bool): pad each item on the left, so that numbers line
            up on the right (the default), or on the right

    Returns:
        list: List of formatted lines
    """
    if not strings:
        return []

    def get_column_widths(strings, items_per_line):
        """Calculate the maximum width for each column."""
        widths = [0] * items_per_line
        for i in range(0, len(strings), items_per_line):
            line = strings[i:i + items_per_line]
            for j, item in enumerate(line):
                widths[j] = max(widths[j], len(item))
        return widths

    # loop through the possible values for items_per_line
    if items_per_line_already_known:
        # Loop once only at the specified number of items
        items_per_line_range = range(items_per_line_already_known, items_per_line_already_known-1, -1)
    else:
        # Loop through the possible numbers of items per line, most first.
        #
        # Each item is at least as long as the shortest one, and is followed by
        # ", " (except the last on a line), so no more than this many items
        # can fit on a line. Starting here rather than at len(strings) means a
        # long list (e.g. a large block of data bytes) doesn't take quadratic
        # time.
        shortest = min(len(str(s)) for s in strings)
        most_that_could_fit = max(1, (max_width + 2) // (shortest + 2))
        items_per_line_range = range(min(len(strings), most_that_could_fit), 0, -1)

    # Try different numbers of items per line
    for items_per_line in items_per_line_range:
        # Check if this arrangement fits within max_width
        # Calculate column widths for this arrangement
        column_widths = get_column_widths(strings, items_per_line)

        # Calculate total line width including commas and spaces
        total_width = sum(column_widths) + (items_per_line - 1) * 2  # 2 chars for ", "

        # If it now fits, or it's the last possible value for items_per_line, then accept it.
        if (total_width <= max_width) or (items_per_line == (items_per_line_range.stop+1)):
            result = []
            for i in range(0, len(strings), items_per_line):
                line = strings[i:i + items_per_line]
                # Format each item to its column width
                formatted_items = []
                for item, width in zip(line, column_widths):
                    if right_align:
                        formatted_items.append(f"{str(item):>{width}}")
                    else:
                        formatted_items.append(f"{str(item):<{width}}")
                result.append(formatter_for_line(", ".join(formatted_items), i, min(i+items_per_line, len(strings))))
            return result

    # If no arrangement works, format one item per line. (This doesn't happen,
    # since one item per line is always accepted above.)
    return [formatter_for_line(str(item), i, i + 1) for i, item in enumerate(strings)]

class StackEntry:
    """One frame of the call stack (see get_callstack()): its 'index' (0
    for the innermost), the 'function' it's in, and its 'filename' and line
    number ('lineno')."""

    def __init__(self, index, function, filename, lineno):
        self.index = index
        self.function = function
        self.filename = filename
        self.lineno = lineno

    @property
    def code(self):
        """The line of source code (looked up only when needed, since it's slow)."""
        line = linecache.getline(self.filename, self.lineno).strip()
        return line if line else None

    def __str__(self):
        return "{0}({1}): In function {2}(): line '{3}'".format(self.filename, self.lineno, self.function, self.code)

    def __repr__(self) -> str:
        return self.__str__()

def get_callstack():
    """
    Gathers the current callstack.

    Returns:
        list of call stack information where each entry is a 'StackEntry' object,
        starting with this function's own frame
    """

    # (This walks the frames directly rather than using inspect.stack(), which
    # is much slower since it reads the source code of every frame.)
    library_frames = []
    frame = sys._getframe(0)
    i = 0
    while frame is not None:
        code = frame.f_code
        library_frames.append(StackEntry(i, code.co_name, code.co_filename, frame.f_lineno))
        frame = frame.f_back
        i += 1

    return library_frames

def show_callstack():
    """Print the call stack that led here, innermost first, as debug messages
    (leaving out this function and get_callstack()). For debugging py8dis."""
    callstack = get_callstack()[2:]
    for entry in callstack:
        debug(entry)

def find_external_callstack():
    """
    Return the callstack as a list of 'StackEntry' objects, taking out any calls within this library

    What's left is the control file's part of the call stack, i.e. the
    lines of the control file that led here. classification.String keeps
    this, to say which command made a string (in its str(), for
    debugging). A frame is taken to be
    py8dis's own if its file's path contains library_path, so a control file
    kept in py8dis's own folder (which README.md suggests as a way round
    setting PYTHONPATH) is left out too.
    """
    frames = get_callstack()
    return [f for f in frames if library_path not in f.filename]
