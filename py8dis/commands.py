"""
Exposes useful commands to the user:

load()                  Loads a binary file to analyse.
load_prg()              Loads a Commodore PRG file, at the address in its first two bytes.
move()                  Indicates that a block of memory is copied at runtime.
label()                 Define a label name for a runtime address.
optional_label()        Define a label name for a runtime address, if used.
local_label()           Define a label name for a runtime address within a memory range.
memory_region()         Name a region of memory, to group the list of memory locations.
addr()                  Returns the runtime address of the given label name.
get_label()             Get the label for a specified address.
set_label_maker_hook()  Sets a user defined 'hook' function that can make label names.

constant()              Define a name for a constant value.

comment()               Add a comment, with word_wrapping by default.
formatted_comment()     Add a comment, with no word wrapping.

subroutine()            Define a subroutine.

byte()                  Categorise 8 bit bytes at the given address as byte data.
word()                  Categorise 16 bit words at the given address as word data.
stringterm()            Terminates at a specified value.
stringcr()              Terminates at ASCII code 13.
stringz()               Terminates at ASCII code 0.
string()                Terminates at a non-printable character, or the given length.
stringhi()              Terminates at a top-bit-set character, final character optional.
stringhiz()             As stringhi, but also terminates at zero.
stringn()               The first byte holds the length, followed by the string.

entry()                 Specifies that there is code at the given address.
wordentry()             Marks a sequence of data words as being addresses of code.
code_ptr()              Marks two bytes of data as being a subroutine's address.
rts_code_ptr()          Marks two bytes of data as being an RTS-able subroutine address.
nonentry()              Marks an address as 'not to be traced as code'.
hook_subroutine()       For functions that don't return normally, control the tracing.

expr()                  Define an expression equivalent to an 8 bit data byte.
expr_label()            Define an expression equivalent to a 16 bit runtime address.

annotate()              Add a raw string directly to the assembly code output.
blank()                 Add a blank line directly to the assembly code output.

get_u8_binary()         Read a single byte of data from the specified address.
get_u16_binary()        Read a 16 bit value (little endian) from the specified address.
get_u16_be_binary()     Read a 16 bit value (big endian) from the specified address.

char()                  Specifies quoted character (e.g. 'a') formatting.
binary()                Specifies binary (e.g. %010110111) formatting.
picture_binary()        Specifies picture binary (e.g. %#.####.#) formatting.
decimal()               Specifies decimal formatting.
hexadecimal()           Specifies hex formatting.
uint()                  Specifies uint formatting.
padded_uint()           Specifies padded uint formatting.
set_formatter()         Specifies a function used to format data.

include_binary_file()   Include a binary file into the assembly.

go()                    Classifies code and data and emits assembly.
reset()                 Forget everything, ready to disassemble something else.
use_command_line()      Turn off (or on) reading options such as --acme from the command line.
"""

import memorymanager

# These functions are directly exposed to the user.
from disassembly import get_label
from align import Align
from format import Format
from binaryaddrtype import BinaryAddrType
from session import use_command_line
from maker import make_op1, make_op2, make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo

# These modules are used to implement things in this file and aren't so directly
# exposed to the user. The user can still access them using the qualified names
# if they wish, since a control file will usually do import * from this module.
import classification
import config
import expression
import disassembly
import labelmanager
import movemanager
import mainformatter
import align
import session
import trace
import utils

import cpu
import snippets6502
import cpu65C02
import cpu6510
import textencoding
import cpu6502
import cpu8080

cpu_names = { "6502"  : cpu6502.Cpu6502,
              "65c02" : cpu65C02.Cpu65C02,
              "6510"  : cpu6510.Cpu6510,
              "8080"  : cpu8080.Cpu8080,
            }

memory_binary = memorymanager.memory_binary
memory        = memorymanager.memory

# User input is checked with these (and utils.die()) rather than with 'assert',
# since 'python -O' removes asserts.
def _hex(value):
    return config.get_assembler().hex(value)

def _show(value):
    """Format a value for an error message: in hex if it could be an address."""
    if utils.is_integer_type(value) and value >= 0:
        return _hex(value)
    return repr(value)

def _check_address_range(command, addr, allow_end=False):
    """Stop with an error unless addr is an integer address in memory. If
    allow_end is True then &10000 (just past the end of memory) is allowed."""
    top = 0x10000 if allow_end else 0xffff
    if not utils.is_integer_type(addr) or not (0 <= addr <= top):
        utils.die("{0}({1}): the address must be between {2} and {3}".format(command, _show(addr), config.get_assembler().hex4(0), _hex(top)))

def _check_addr(command, runtime_addr, allow_end=False):
    """Check a runtime address given by the user, returning it as a RuntimeAddr."""
    _check_address_range(command, runtime_addr, allow_end)
    return memorymanager.RuntimeAddr(runtime_addr)

def _check_count(command, runtime_addr, n, arg_name="n"):
    """Check that n (a number of bytes, words etc) is a positive integer."""
    if not utils.is_integer_type(n) or n <= 0:
        utils.die("{0}({1}, ...): {2} must be a positive integer, not {3!r}".format(command, _show(runtime_addr), arg_name, n))

def _check_name(command, runtime_addr, name, allow_expression=True):
    """Check a label name given by the user. Unless allow_expression is False,
    the name can be an expression (e.g. 'table+1') rather than a simple name."""
    if not isinstance(name, str) or name == "":
        utils.die("{0}({1}, {2!r}): the name must be a non-empty string".format(command, _show(runtime_addr), name))
    if not allow_expression and not disassembly.is_simple_name(name):
        utils.die("{0}({1}, {2!r}): this isn't a valid label name (a letter or underscore followed by letters, digits or underscores)".format(command, _show(runtime_addr), name))

def _as_text(name):
    """A label name or expression can be given as an expression made by e.g.
    make_add(). If so, it's converted to text (unless it refers to a label that
    isn't named yet)."""
    if isinstance(name, expression.Expr) and not name.is_lazy():
        return str(name)
    return name

def _check_move_id(command, runtime_addr, move_id):
    """Check a move_id given by the user (None is allowed)."""
    if move_id is not None and not (utils.is_integer_type(move_id) and movemanager.is_valid_move_id(move_id)):
        utils.die("{0}({1}, ...): move_id must be a value returned by move(), not {2!r}".format(command, _show(runtime_addr), move_id))

def _check_in_memory(command, runtime_addr, binary_addr, n=1, count=None):
    """Stop with an error if the n bytes from binary_addr run past the top of
    memory. 'count' is the count the user gave, if different from n."""
    if binary_addr + n > 0x10000:
        utils.die("{0}({1}, {2}): this runs past the top of memory".format(command, _hex(runtime_addr), n if count is None else count))

def _check_data_loaded(command, runtime_addr, binary_addr, n=1):
    """Stop with an error unless there is data loaded at all n bytes from binary_addr."""
    _check_in_memory(command, runtime_addr, binary_addr, n)
    if not memorymanager.is_data_loaded_at_binary_addr(binary_addr, n):
        utils.die("{0}({1}): no data is loaded at this address ({2})".format(command, _hex(runtime_addr), memorymanager.describe_loaded_files()))

# Reading the binary. (These check the user's address, then use the
# memorymanager functions of the same name.)
def get_u8_binary(binary_addr):
    """Read a single byte of data from the specified binary address."""
    _check_address_range("get_u8_binary", binary_addr)
    _check_data_loaded("get_u8_binary", binary_addr, binary_addr, 1)
    return memorymanager.get_u8_binary(memorymanager.BinaryAddr(binary_addr))

def get_u16_binary(binary_addr):
    """Read a 16 bit value (little endian) from the specified binary address."""
    _check_address_range("get_u16_binary", binary_addr)
    _check_data_loaded("get_u16_binary", binary_addr, binary_addr, 2)
    return memorymanager.get_u16_binary(memorymanager.BinaryAddr(binary_addr))

def get_u16_be_binary(binary_addr):
    """Read a 16 bit value (big endian) from the specified binary address."""
    _check_address_range("get_u16_be_binary", binary_addr)
    _check_data_loaded("get_u16_be_binary", binary_addr, binary_addr, 2)
    return memorymanager.get_u16_be_binary(memorymanager.BinaryAddr(binary_addr))

def get_u16_be_runtime(runtime_addr):
    """Read a 16 bit value (big endian) from the specified runtime address."""
    runtime_addr = _check_addr("get_u16_be_runtime", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_data_loaded("get_u16_be_runtime", runtime_addr, binary_loc.binary_addr, 2)
    return memorymanager.get_u16_be_binary(binary_loc.binary_addr)

def load(binary_load_addr, filename, cpu_name="6502", md5sum=None, *, offset=0, length=None):
    """Loads a binary file to analyse at the given address.

    Load a binary file and optionally verify the checksum of the data (of the
    whole file). To load only part of the file, give the offset in the file
    to start from, and the length to load (or None for the rest of the
    file)."""

    _check_address_range("load", binary_load_addr)
    command = "load({0}, {1!r})".format(_hex(binary_load_addr), filename)
    if not utils.is_integer_type(offset) or offset < 0:
        utils.die("{0}: the offset must be a whole number, 0 or more, not {1!r}".format(command, offset))
    if length is not None and (not utils.is_integer_type(length) or length <= 0):
        utils.die("{0}: the length must be a positive whole number (or None for the rest of the file), not {1!r}".format(command, length))
    _select_cpu(cpu_name)

    # A PRG file's first two bytes are its load address, not part of the data
    if offset == 0 and filename.lower().endswith((".prg", ".p00")):
        utils.warn("{0}: this looks like a Commodore PRG file, whose first two bytes are the address to load it at, not data; load_prg({1!r}) loads it at that address without them".format(command, filename))

    memorymanager.load(filename, binary_load_addr, md5sum, offset, length, command=command)

def load_prg(filename, cpu_name="6502", md5sum=None):
    """Loads a Commodore PRG file: its first two bytes are the address to load
    the rest of it at. (A PC64 'P00' file, a PRG file after a 26 byte header
    starting 'C64File', is also accepted.)

    The disassembly starts with the same two bytes, so that it assembles to
    the whole PRG file. (To load the data without them, use
    load(address, filename, offset=2).) The md5sum, if given, is that of the
    whole file. Returns the load address."""

    command = "load_prg({0!r})".format(filename)
    def die(problem):
        utils.die("{0}: {1}".format(command, problem))
    _select_cpu(cpu_name)

    data = memorymanager.read_file(filename, die)
    header_length = 26 if data[:8] == b"C64File\0" else 0
    if len(data) < header_length + 3:
        die("the file ({0} bytes) is too short to be a PRG file (two bytes of load address, then the data)".format(len(data)))
    binary_load_addr = data[header_length] | (data[header_length + 1] << 8)
    memorymanager.load(filename, binary_load_addr, md5sum, header_length + 2, prg=True, command=command)
    return binary_load_addr

def _select_cpu(cpu_name):
    """Check the CPU asked for by load() or load_prg() is supported by the
    chosen assembler, and make it the session's CPU (or check it's the same
    type as one chosen by an earlier load())."""
    if cpu_name is None:
        utils.die("No CPU type selected in call to load().")

    if isinstance(cpu_name, cpu.Cpu):
        # Set the CPU (or keep the one from an earlier load(), if it's the
        # same type of CPU, as with a CPU given by name below)
        current_cpu = session.current().cpu
        if current_cpu is None:
            session.current().cpu = cpu_name
        elif type(current_cpu) is not type(cpu_name):
            utils.die("All calls to load() must use the same CPU (already using '%s', now asked for '%s')." % (type(current_cpu).__name__, type(cpu_name).__name__))
    else:
        cpu_name = cpu_name.lower()

        # Get the list of supported CPUs for the assembler in lower case
        assembler_cpus_supported = [x.lower() for x in config.get_assembler().cpus_supported()]

        # Check the assembler can handle the CPU chosen
        if not cpu_name in assembler_cpus_supported:
            utils.die("Cpu '%s' is not supported by the chosen assembler. See call to load()" % (cpu_name))

        # Set the CPU
        if cpu_name not in cpu_names:
            utils.die("Unknown CPU or missing CPU parameter '%s' specified for load()." % (cpu_name))
        cpu_class = cpu_names[cpu_name]
        if session.current().cpu is None:
            session.current().cpu = cpu_class()
        elif type(session.current().cpu) is not cpu_class:
            # Only create the CPU once: creating it again would discard any
            # entry points, hooks etc already added after an earlier load().
            utils.die("All calls to load() must use the same CPU (already using '%s', now asked for '%s')." % (type(session.current().cpu).__name__, cpu_name))

    # The 65C02 has extra instructions, which some assemblers need to be told
    # about (see get_cmos())
    if isinstance(session.current().cpu, cpu65C02.Cpu65C02):
        config.set_cmos(True)

def move(dest_runtime_addr, src_binary_addr, length):
    """Indicates that a block of memory is copied at runtime.

    Often a block of code or data is moved (relocated) after loading
    but before being used at runtime. For example, BBC Micro games that
    load at $1900 may relocate bits or even all of themselves down to
    $e00 before being used.

    This function specifies such a move, indicating that the runtime
    address is different from the loaded address for a block of memory.
    This allows labels within the block to be properly defined by their
    runtime addresses.

    move()s should be called before accessing the relocated block.
    As a simple rule put any move() commands first, directly after
    load().
    """

    memory_binary = session.current().memory.binary
    def describe():
        h = config.get_assembler().hex
        return "move({0}, {1}, {2})".format(h(dest_runtime_addr), h(src_binary_addr), length)

    if length <= 0:
        utils.die("{0}: the length must be greater than zero".format(describe()))
    if not (0 <= dest_runtime_addr and dest_runtime_addr + length <= 0x10000):
        utils.die("{0}: the destination runs past the top of memory".format(describe()))
    if not (0 <= src_binary_addr and src_binary_addr + length <= 0x10000):
        utils.die("{0}: the source runs past the top of memory".format(describe()))
    if dest_runtime_addr == src_binary_addr:
        utils.die("{0}: the source and destination are the same".format(describe()))

    # You can't move from a region that hasn't been populated with data.
    for i in range(src_binary_addr, src_binary_addr + length):
        if memory_binary[i] is None:
            utils.die("{0}: no data is loaded at {1} ({2})".format(describe(), config.get_assembler().hex(i), memorymanager.describe_loaded_files()))

    dest_runtime_addr = memorymanager.RuntimeAddr(dest_runtime_addr)
    src_binary_addr = memorymanager.BinaryAddr(src_binary_addr)
    return movemanager.add_move(dest_runtime_addr, src_binary_addr, length)

def constant(value, name, comment=None, *, align=Align.INLINE, format=Format.DEFAULT):
    """Give a name to a constant value for use in the assembly.

    These names can then be used in subsequent calls to expr().
    """
    def check(ok, problem):
        if not ok:
            utils.die("constant({0}, {1!r}): {2}".format(value, name, problem))
    check(isinstance(name, str) and name != "" and disassembly.is_simple_name(name), "the name must be a valid label name (a letter or underscore followed by letters, digits or underscores)")
    check(comment is None or isinstance(comment, str), "the comment must be a string, not {0!r}".format(comment))
    check(isinstance(align, Align), "align must be an Align value (e.g. Align.INLINE), not {0!r}".format(align))
    check(isinstance(format, Format), "format must be a Format value (e.g. Format.HEX), not {0!r}".format(format))

    disassembly.add_constant(value, name, comment, align, format)

def label(runtime_addr, name, move_id=None):
    """Define a label name for a runtime address."""
    _label("label", runtime_addr, name, move_id)

def _label(command, runtime_addr, name, move_id=None):
    runtime_addr = _check_addr(command, runtime_addr, allow_end=True) # &10000 is valid for labels
    name = _as_text(name)
    _check_name(command, runtime_addr, name)
    _check_move_id(command, runtime_addr, move_id)
    if move_id is None:
        # Look up the associated binary address, just to get the best move_id
        _, move_id = movemanager.r2b(runtime_addr)

    disassembly.add_label(runtime_addr, name, move_id, is_autogenerated=False)

def expr_label(runtime_addr, s):
    """Define an expression for a runtime address.

    Defines a string expression to be output when the given
    runtime address is referenced.

    An expression is a string containing labels and/or other
    arithmetic calculations that the assembler can interpret. When
    the given address is referenced by code, the string expression
    is output instead.

    e.g. the command expr_label(0x1234, "my_table+1") would change
    all instances of 'lda $1234' to 'lda my_table+1'.

    Assembler assertions output at the end of the assembly code ensure
    that the expressions evaluate to the expected constants."""

    return _label("expr_label", runtime_addr, s)

def memory_region(start_addr, end_addr, name):
    """Name a region of memory, from start_addr up to (but not including)
    end_addr, e.g. memory_region(0xfc00, 0xff00, "Hardware").

    The "Memory locations" list at the top of the output (the labels defined
    as 'name = value') is grouped by region, under headings. Regions can
    overlap: each label goes in the smallest region that contains it, so a
    region can be named within a larger one, e.g. some workspace within zero
    page. Of two regions the same size, the one named last is used, so a
    region can be renamed by naming it again. (The 6502's zero page and stack
    are regions already, and acorn.bbc() etc. name the regions of the Acorn
    machines' memory, so e.g. memory_region(0x0400, 0x0800, "BASIC
    workspace") after acorn.bbc() renames its language workspace.)

    An empty name removes the region with that range, so its labels go in the
    next larger region that contains them, or under "Other" if there's none,
    e.g. memory_region(0x0400, 0x0800, "") after acorn.bbc()."""
    start_addr = _check_addr("memory_region", start_addr)
    end_addr = _check_addr("memory_region", end_addr, allow_end=True)
    if end_addr <= start_addr:
        utils.die("memory_region({0}, {1}, ...): the end must be after the start".format(_hex(start_addr), _hex(end_addr)))
    if not isinstance(name, str):
        utils.die("memory_region({0}, {1}, ...): the name must be a string, not {2!r}".format(_hex(start_addr), _hex(end_addr), name))
    disassembly.add_memory_region(start_addr, end_addr, name)

def optional_label(runtime_addr, name, base_runtime_addr=None, *, definable_inline=True):
    """Set a label at a runtime address, but only output if used.

    When two consecutive bytes share a label (e.g. `userv` and `userv+1`) then `base_runtime_addr` points to the first byte."""

    runtime_addr = _check_addr("optional_label", runtime_addr)
    name = _as_text(name)
    # (With a base address the name can be an expression, e.g. 'userv+1')
    _check_name("optional_label", runtime_addr, name, allow_expression=base_runtime_addr is not None)
    if base_runtime_addr is not None:
        base_runtime_addr = _check_addr("optional_label", base_runtime_addr)
    disassembly.add_optional_label(runtime_addr, name, base_addr=base_runtime_addr, definable_inline=definable_inline)

def local_label(runtime_addr, name, start_addr, end_addr, move_id=None):
    """Define a label name for a runtime address but only within a given memory range"""

    runtime_addr = _check_addr("local_label", runtime_addr, allow_end=True)
    _check_name("local_label", runtime_addr, name, allow_expression=False)
    _check_address_range("local_label", start_addr, allow_end=True)
    _check_address_range("local_label", end_addr, allow_end=True)
    _check_move_id("local_label", runtime_addr, move_id)
    disassembly.add_local_label(runtime_addr, name, start_addr, end_addr, move_id)

def substitute_constants(instruction, reg, constants_dict, define_all_constants=None):
    """Substitute a name or expression from a dictionary whenever a load
    immediate to a given register is done before the given instruction.
    e.g. Supply a list of sprite id names to 'lda #15:jsr sprite_plot'

    `define_all_constants` has three possible values:
        None    - define no constants (the default)
        False   - define only the constants used
        True    - define all constants
    """

    if define_all_constants:
        for entry in constants_dict:
            if disassembly.is_simple_name(constants_dict[entry]):
                constant(entry, constants_dict[entry])

    session.current().trace.substitute_constant_list.append(cpu6502.SubConst(instruction, reg, constants_dict, define_all_constants is not None))

def subroutine(runtime_addr, name=None, title=None, description=None, on_entry=None, on_exit=None, hook=None, move_id=None, is_entry_point=True):
    """
    Define a subroutine.

    All parameters except the address are optional. These are used to
    create a header comment above the definition of the subroutine.

    They are also used to decorate calling code with explanatory text.
    This is done by the default hook function when hook=None (the
    default). If this is not wanted specify hook=False.
    """
    runtime_addr = _check_addr("subroutine", runtime_addr)
    _check_move_id("subroutine", runtime_addr, move_id)
    for (arg, value) in (("on_entry", on_entry), ("on_exit", on_exit)):
        if value is not None and not isinstance(value, dict):
            utils.die("subroutine({0}, ...): {1} must be a dictionary (e.g. {{'a': 'the value'}}), not {2!r}".format(_hex(runtime_addr), arg, value))
    if name is not None and len(name)>0:
        if is_entry_point:
            entry(runtime_addr, name)
        else:
            optional_label(runtime_addr, name, definable_inline=True)

    if hook is False:
        # No decoration of calling code wanted
        hook = None
    elif hook is None:
        # Use the CPU's default hook function, if it has one. This is looked
        # up when the hook is called, since subroutine() may be called before
        # load() has chosen the CPU.
        def hook(runtime_addr, state, subroutine):
            default_hook = getattr(session.current().cpu, "default_subroutine_hook", None)
            if default_hook is not None:
                default_hook(runtime_addr, state, subroutine)

    runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    # if the subroutine in within the binary, output a header comment for it.
    if memorymanager.is_data_loaded_at_binary_addr(binary_loc.binary_addr):
        # Format a comment for the subroutine header
        if config.get_subroutine_header() is not None:
            auto_comment(runtime_addr, config.get_subroutine_header(), word_wrap=False)
        com = ""
        middle = ""
        if title is not None and len(title)>0:
            middle += title + "\n"
        if description is not None and len(description)>0:
            middle += "\n" + description + "\n"
        if on_entry is not None and len(on_entry)>0:
            middle += "\nOn Entry:\n"
            for reg in on_entry:
                middle += config.get_indent_string() + reg.upper() + ": " + on_entry[reg] + "\n"
        if on_exit is not None and len(on_exit)>0:
            middle += "\nOn Exit:\n"
            for reg in on_exit:
                middle += config.get_indent_string() + reg.upper() + ": " + on_exit[reg] + "\n"
        if middle.startswith("\n"):
            middle = middle[1:]
        if middle.endswith("\n"):
            middle = middle[:-1]
        if len(middle)>0:
            auto_comment(runtime_addr, middle)
            if config.get_subroutine_footer() is not None:
                auto_comment(runtime_addr, config.get_subroutine_footer(), word_wrap=False)
    trace.add_subroutine(runtime_addr, name, title, description, on_entry, on_exit, hook, move_id)

def _convert_inline_to_align_internal(inline, align, command="comment"):
    # If no 'align' value is specified, convert the old True/False 'inline' values into the modern 'Align' type
    if align is None:
        if inline:
            align = Align.INLINE
        else:
            align = Align.BEFORE_LABEL

    if not isinstance(align, Align):
        utils.die("{0}(): align must be an Align value (e.g. Align.INLINE), not {1!r}".format(command, align))
    return align

def comment(runtime_addr, text, inline=False, indent=0, word_wrap=True, *, align=None):
    """Add a comment.

    Define a comment string to appear in the assembly code at the
    given address in the output. The comment can be inlined (added
    to the end of the line), or standalone (a separate line of output).
    The comment is word wrapped by default.
    """
    runtime_addr = _check_addr("comment", runtime_addr)
    _check_data_loaded("comment", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr)
    def check(ok, problem):
        if not ok:
            utils.die("comment({0}, ...): {1}".format(_hex(runtime_addr), problem))
    check(isinstance(inline, bool),    "inline must be True or False, not {0!r}".format(inline))
    check(isinstance(indent, int),     "indent must be an integer, not {0!r}".format(indent))
    check(isinstance(word_wrap, bool), "word_wrap must be True or False, not {0!r}".format(word_wrap))

    # Convert the old True/False values into the modern 'Align' type as needed
    align = _convert_inline_to_align_internal(inline, align)

    disassembly.comment(runtime_addr, text, word_wrap=word_wrap, indent=indent, align=align, auto_generated=False)

def formatted_comment(runtime_addr, text, inline=False, align=None, indent=0):
    """Add a comment without word wrapping."""
    runtime_addr = _check_addr("formatted_comment", runtime_addr)
    _check_data_loaded("formatted_comment", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr)

    # Convert the old True/False values into the modern 'Align' type as needed
    align = _convert_inline_to_align_internal(inline, align, "formatted_comment")

    disassembly.comment(runtime_addr, text, word_wrap=False, indent=indent, align=align)

def no_automatic_comment(runtime_addr):
    """Inhibits the output of any automatically generated comment at the given address"""
    runtime_addr = _check_addr("no_automatic_comment", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    session.current().trace.no_auto_comment_set.add(binary_loc.binary_addr)

def auto_comment(runtime_addr, text, inline=False, align=None, indent=0, show_blank=False, word_wrap=True):
    """For internal use only. Generates a comment if not inhibited."""

    if runtime_addr is None:
        return

    # Convert the old True/False values into the modern 'Align' type as needed
    align = _convert_inline_to_align_internal(inline, align)

    # Make sure we are within the binary
    runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
    binary_addr, _ = movemanager.r2b(runtime_addr)
    if binary_addr is not None:
        if memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            if show_blank:
                blank(runtime_addr)
            disassembly.comment(runtime_addr, text, word_wrap=word_wrap, indent=indent, align=align, auto_generated=True)

def annotate(runtime_addr, s, *, align=Align.BEFORE_LABEL, priority=None, once_only=False):
    """Add a raw string directly to the assembly code output at the
    given address."""

    runtime_addr = _check_addr("annotate", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    disassembly.annotate_binary(binary_loc, s, align=align, priority=priority, once_only=once_only)

def blank(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None):
    annotate(runtime_addr, "", align=align, priority=priority)

def blank_once(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None):
    annotate(runtime_addr, "", align=align, priority=priority, once_only=True)

def expr(runtime_addr, s, force=True):
    """Define a string expression for an address.

    A string expression is output at the given runtime address
    instead of a regular numerical value.

    An expression is a string containing labels, constants and/or other
    arithmetic calculations that the assembler can interpret. When the
    given address reached, the regular output is replaced by the string
    expression.

    e.g. 'lda #$30' might be replaced by 'lda #>screen_address'

    Alternatively, a dictionary can be supplied with integer keys and
    string values. The byte found at the address is used as the key,
    and is replaced with the expression string value.
    """

    runtime_addr = _check_addr("expr", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_data_loaded("expr", runtime_addr, binary_loc.binary_addr)

    if isinstance(s, dict):
        # Dictionary supplied.
        # Look up value in binary, and use that as key in dictionary
        val = get_u8_binary(binary_loc.binary_addr)
        if val not in s:
            utils.die("expr({0}, ...): the dictionary has no entry for the value {1} found at this address".format(_hex(runtime_addr), _hex(val)))
        s = s[val]

    # (This isn't auto_generated even when called from auto_expr(), since
    # auto_expr() itself checks for no_automatic_comment())
    classification.add_expression(binary_loc.binary_addr, s, force=force, auto_generated=False)

def auto_expr(runtime_addr, s):
    """For internal use only. Called internally in order to generate an expression, such as 'end_address - start_address' etc."""

    if runtime_addr is None:
        return

    # Make sure we are within the binary
    runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    if not (binary_loc.binary_addr in session.current().trace.no_auto_comment_set):
        if memorymanager.is_data_loaded_at_binary_addr(binary_loc.binary_addr):
            expr(runtime_addr, s, force=False)

def _is_loaded_else_warn(command, runtime_addr, binary_addr, n, consequence, warn=True):
    """Returns True if data is loaded at all n bytes from binary_addr. If not,
    and 'warn' is True, warns the user with the given consequence."""
    if memorymanager.is_data_loaded_at_binary_addr(binary_addr, n):
        return True
    if warn:
        utils.warn("{0}({1}): no data is loaded at this address ({2}), so {3}".format(command, _hex(runtime_addr), memorymanager.describe_loaded_files(), consequence))
    return False

def _check_not_classified(command, runtime_addr, binary_addr, length):
    """Stop with an error if any of the bytes are already classified (e.g. as a string)."""
    for i in range(length):
        if classification.is_classified(binary_addr + i, 1):
            utils.die("{0}({1}, ...): {2} has already been classified (e.g. by an earlier byte(), word() or string command)".format(command, _hex(runtime_addr), _hex(runtime_addr + i)))

def byte(runtime_addr, n=1, cols=None):
    """Categorise a number of bytes at the given address as byte data."""

    runtime_addr = _check_addr("byte", runtime_addr)
    _check_count("byte", runtime_addr, n)
    if cols is not None:
        _check_count("byte", runtime_addr, cols, "cols")
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_in_memory("byte", runtime_addr, binary_loc.binary_addr, n)
    if not _is_loaded_else_warn("byte", runtime_addr, binary_loc.binary_addr, n, "this is ignored"):
        return
    _check_not_classified("byte", runtime_addr, binary_loc.binary_addr, n)
    classification.add_classification(binary_loc.binary_addr, classification.Byte(n, cols=cols))

# TODO: byte()/word() should probably optionally (via an optional arg or a variant function)
# allow the user to specify a format hint for the range without having to make a separate call
# to the relevant formatter function with the same arguments. Just maybe an optional argument
# "format_command=None" where we do "if format_command is not None: format_command(runtime_addr, n)"
# would work, then you could do "word(0x432, 4, picture_binary)" (if we squeezed formatter in before
# warn=True argument; this is all getting a smidge messy, especially if the user is forced to specify
# 1 for the n argument) - anyway, think about it...
def word(runtime_addr, n=1, cols=None):
    """Categorise a number of 16 bit words at the given address as word data."""

    runtime_addr = _check_addr("word", runtime_addr)
    _check_count("word", runtime_addr, n)
    if cols is not None:
        _check_count("word", runtime_addr, cols, "cols")
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_in_memory("word", runtime_addr, binary_loc.binary_addr, n * 2, count=n)
    if not _is_loaded_else_warn("word", runtime_addr, binary_loc.binary_addr, n * 2, "this is ignored"):
        return
    _check_not_classified("word", runtime_addr, binary_loc.binary_addr, n * 2)
    classification.add_classification(binary_loc.binary_addr, classification.Word(n * 2, cols=cols))

def entry(runtime_addr, label=None, warn=True):
    """
    Specifies that there is code at the given runtime address.

    When go() is called, code is automatically traced from each entry
    point through all possible branches and subroutines. This is
    categorised as code, and therefore output as instructions.
    """

    runtime_addr = _check_addr("entry", runtime_addr)
    if label is not None:
        _check_name("entry", runtime_addr, label)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    _is_loaded_else_warn("entry", runtime_addr, binary_loc.binary_addr, 1, "there is no code here to trace", warn)

    session.current().cpu.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, label, explicit=True)

    result = disassembly.get_label(runtime_addr, binary_loc.binary_addr, move_id=binary_loc.move_id, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_DEFINITION)

    return result

def nonentry(runtime_addr):
    """
    Marks an address as 'not to be traced as code'.

    See entry() for details of tracing. When the tracing of code
    reaches the given address then tracing stops. For example,
    when a conditional branch is in practice always taken at runtime,
    any following code is never executed. Use of this command is
    rare.
    """

    runtime_addr = _check_addr("nonentry", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_data_loaded("nonentry", runtime_addr, binary_loc.binary_addr)

    session.current().cpu.traced_entry_points.add(binary_loc.binary_addr)

def wordentry(runtime_addr, n=1):
    """
    Marks a sequence of data words as being addresses of code.

    For a table of words where each entry is the address of some code,
    this both categorises the data as words, and substitutes label names
    as appropriate.
    """

    runtime_addr = _check_addr("wordentry", runtime_addr)
    _check_count("wordentry", runtime_addr, n)
    word(runtime_addr, n)
    for i in range(n):
        binary_loc = movemanager.r2b_checked(runtime_addr)
        _check_data_loaded("wordentry", runtime_addr, binary_loc.binary_addr, 2)
        entry_runtime_addr = get_u16_binary(binary_loc.binary_addr)
        entry_label = entry(entry_runtime_addr)
        expr(runtime_addr, entry_label)

        runtime_addr += 2

    return runtime_addr

def hook_subroutine(runtime_addr, name, hook, warn=True):
    """
    Add a hook function for a subroutine at the given address.

    When executed, an unusual subroutine may not return right after it
    was called. For the purpose of tracing the code, we need to know
    where code will continue to be executed. The hook_subroutine()
    function can be used to specify a 'hook' routine that determines
    where execution continues after the subroutine finishes.

    There is a common use case: A subroutine that 'prints the following
    string' has a call to a subroutine followed by a string definition.
    Execution only continues *after* the string definition.

    The following '*_hook' functions are designed to be used as the
    'hook' parameter, to determine the end of the string.
    """

    runtime_addr = _check_addr("hook_subroutine", runtime_addr)
    _check_name("hook_subroutine", runtime_addr, name)
    _is_loaded_else_warn("hook_subroutine", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr, 1,
        "there is no code here to trace (use warn=False for a subroutine outside the binary)", warn)
    session.current().cpu.hook_subroutine(runtime_addr, name, hook)

def stringhi_hook(target, addr):
    return stringhi(addr + 3)

def stringhiz_hook(target, addr):
    return stringhiz(addr + 3)

def stringcr_hook(target, addr):
    return stringcr(addr + 3)

def stringz_hook(target, addr):
    return stringz(addr + 3)

def stringn_hook(target, addr):
    return stringn(addr + 3)

def code_ptr(runtime_addr, runtime_addr_high=None, offset=0, label_name=None):
    """
    Marks two bytes of data as being the address of a subroutine.

    The low and high bytes do not need to be stored adjacently since
    their addresses can be specified separately. This is used to handle
    jump tables where the low and high bytes are stored in separate
    tables. An optional offset can be applied to the subroutine
    address.

    Code tracing, see entry(), is applied to the subroutine.
    """

    memory_binary = session.current().memory.binary
    runtime_addr = _check_addr("code_ptr", runtime_addr)
    if runtime_addr_high is None:
        runtime_addr_high = runtime_addr + 1
    runtime_addr_high = _check_addr("code_ptr", runtime_addr_high)
    binary_addr = movemanager.r2b_checked(runtime_addr).binary_addr
    binary_addr_high = movemanager.r2b_checked(runtime_addr_high).binary_addr
    for (r, b) in ((runtime_addr, binary_addr), (runtime_addr_high, binary_addr_high)):
        if not memorymanager.is_data_loaded_at_binary_addr(b):
            utils.die("code_ptr(): no data is loaded at {0} ({1})".format(config.get_assembler().hex(r), memorymanager.describe_loaded_files()))

    # The address of the code, wrapping round at the top of memory (e.g. an
    # 'rts' jump table entry of &ffff means the code is at &0000)
    stored_value = (memory_binary[binary_addr_high] << 8) | memory_binary[binary_addr]
    code_at_runtime_addr = (stored_value + offset) & 0xffff
    wraps_round = (code_at_runtime_addr != stored_value + offset)

    # Label and trace the code at code_at
    label = entry(code_at_runtime_addr, label=label_name, warn=False)
    # Reference that label at addr/addr_high.
    if offset == 0:
        stored_expr = label
    else:
        # e.g. 'label-1' (for an rts jump table)
        stored_expr = expression.Binary(expression.to_expr(label), "-" if offset > 0 else "+", expression.Num(abs(offset)))
    if binary_addr_high == binary_addr + 1 and runtime_addr_high == runtime_addr + 1:
        # The general code in the "else" branch would work for this case as
        # well, but since the assembler has support for emitting a little-endian
        # 16-bit word it's nice to use it when we can.
        if wraps_round:
            # Bring e.g. 'l0000-1' back into the range of a 16-bit word
            stored_expr = make_and(stored_expr, make_hex(0xffff))
        word(runtime_addr)
        expr(runtime_addr, stored_expr)
    else:
        byte(runtime_addr)
        expr(runtime_addr, make_lo(stored_expr))
        byte(runtime_addr_high)
        expr(runtime_addr_high, make_hi(stored_expr))
    if abs(runtime_addr_high - runtime_addr) == 1:
        return max(runtime_addr, runtime_addr_high) + 1
    return None

def rts_code_ptr(runtime_addr, runtime_addr_high=None):
    """
    Marks two bytes of data as being the address of a subroutine.

    This is the same as code_ptr() with offset=1. Designed for use when
    pushing an address onto the stack before transferring control by
    executing 'rts'.
    """
    return code_ptr(runtime_addr, runtime_addr_high, offset=1)

def set_label_maker_hook(hook):
    """
    Sets a user defined 'hook' function that can make label names.

    Given an address, the user supplied function should return
    a unique label name or just return the suggested name.

    Sometimes having a routine to make label names can be useful. For
    example, labels at addresses that just 'rts' to early out of a
    subroutine can be labelled uniformly as 'return1', 'return2' etc.
    """

    if session.current().disassembly.user_label_maker_hook is not None:
        utils.die("set_label_maker_hook() can only be called once")
    disassembly.set_user_label_maker_hook(hook)

def addr(label_name):
    """Returns the runtime address of the given label name"""

    if not utils.is_string_type(label_name):
        return None

    return labelmanager.addr(label_name)

def set_formatter(runtime_addr, n, formatter):
    """
    Specifies a function used to format data in a block.

    The 'formatter' is a function that given a value to format, returns
    a string.

    This function is used by the following formatting functions.
    """

    _set_formatter("set_formatter", runtime_addr, n, formatter)

def _set_formatter(command, runtime_addr, n, formatter):
    runtime_addr = _check_addr(command, runtime_addr)
    _check_count(command, runtime_addr, n)
    _check_address_range(command, runtime_addr + n - 1)
    for i in range(n):
        binary_loc = movemanager.r2b_checked(runtime_addr + i)
        session.current().disassembly.format_hint[binary_loc.binary_addr] = formatter

def uhex(runtime_addr, n=1):
    """Specifies unsigned hex formatting for data in the given block"""

    _set_formatter("uhex", runtime_addr, n, mainformatter.uhex_formatter)

def uint(runtime_addr, n=1):
    """Specifies unsigned decimal/hex formatting for data in the given block"""

    # This is nearly the default behaviour, but by specifying a formatter explicitly the
    # automatic addition of a comment showing the corresponding ASCII character for
    # immediate constants will be disabled for this address.
    _set_formatter("uint", runtime_addr, n, mainformatter.uint_formatter)

def uint_no_hex(runtime_addr, n=1):
    """Specifies unsigned decimal integer formatting for data in the given block"""

    _set_formatter("uint_no_hex", runtime_addr, n, mainformatter.uint_no_hex_formatter)

def sint(runtime_addr, n=1):
    """Specifies signed decimal formatting for data in the given block"""

    _set_formatter("sint", runtime_addr, n, mainformatter.sint_formatter)

def padded_uint(runtime_addr, n=1):
    """Specifies padded uint formatting for data in the given block"""

    _set_formatter("padded_uint", runtime_addr, n, lambda n, bits: mainformatter.uint_formatter(n, bits, pad=True))

def char(runtime_addr, n=1):
    """Specifies quoted character formatting for data in the given block"""

    _set_formatter("char", runtime_addr, n, mainformatter.char_formatter)

def binary(runtime_addr, n=1):
    """Specifies binary formatting for data in the given block"""

    _set_formatter("binary", runtime_addr, n, mainformatter.binary_formatter)

def picture_binary(runtime_addr, n=1):
    """Specifies picture binary formatting for data in the given block"""

    _set_formatter("picture_binary", runtime_addr, n, mainformatter.picture_binary_formatter)

def decimal(runtime_addr, n=1):
    """Specifies decimal formatting for data in the given block"""

    _set_formatter("decimal", runtime_addr, n, mainformatter.decimal_formatter)

# "hex" is a Python built-in function so we can't use that.
def hexadecimal(runtime_addr, n=1):
    """Specifies hex formatting for data in the given block"""

    _set_formatter("hexadecimal", runtime_addr, n, mainformatter.hexadecimal_formatter)

def is_assembler(s):
    if config.get_assembler().get_name().lower() == s.lower():
        return True
    return False

##############################################################################
# String functions
##############################################################################
def _encoding(encoding):
    """The textencoding.Encoding for a string command's 'encoding' (a name,
    or None for the session's, see config.set_text_encoding())."""
    return textencoding.current() if encoding is None else textencoding.get(encoding)

def string(runtime_addr, n=None, *, encoding=None):
    """Classifies a part of the binary as a string of given length or
    up to the next non-printable character.

    'encoding' is the string's text encoding (e.g. "petscii", see
    config.set_text_encoding()), if not the session's. The same goes for
    the other string commands.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("string", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    return classification.string_binary(binary_loc.binary_addr, n=n, encoding=_encoding(encoding))

def stringterm(runtime_addr, terminator, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by a given
    terminator byte.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringterm", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringterm_binary(binary_loc.binary_addr, terminator=terminator, exclude_terminator=exclude_terminator, encoding=_encoding(encoding))

def stringcr(runtime_addr, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by ASCII 13.

    Returns the next available memory address after the string."""

    return stringterm(runtime_addr, 13, exclude_terminator, encoding=encoding)

def stringz(runtime_addr, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by ASCII 0.

    Returns the next available memory address after the string."""

    return stringterm(runtime_addr, 0, exclude_terminator, encoding=encoding)

def stringhi(runtime_addr, include_terminator_fn=None, *, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character.

    The string may or may not include the terminator character without
    the top bit.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringhi", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringhi_binary(binary_loc.binary_addr, include_terminator_fn=include_terminator_fn, encoding=_encoding(encoding))

def stringhiz(runtime_addr, include_terminator_fn=None, *, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character or zero character."""

    runtime_addr = _check_addr("stringhiz", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringhiz_binary(binary_loc.binary_addr, include_terminator_fn=include_terminator_fn, encoding=_encoding(encoding))

def stringn(runtime_addr, *, encoding=None):
    """Classifies a part of the binary as a string with the first byte
    giving the length.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringn", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringn_binary(runtime_addr, binary_loc.binary_addr, encoding=_encoding(encoding))

#
# Assembler specific expression strings can be built using these functions:
#

def is_simple_name(s):
    """Check for a string being a single identifier (like 'start_of_table') vs a more complex expression like 'end_address - start_address'"""
    return isinstance(s, str) and s != "" and disassembly.is_simple_name(s)

def split_classification(runtime_addr):
    """Split a single classification into two at the given address. Allows partial strings to be shown on different lines of the output."""
    runtime_addr = _check_addr("split_classification", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    classification.split_classification(binary_loc.binary_addr, warn=False)

def include_binary_file(runtime_addr, relative_filepath):
    """Add an 'include binary' command in the assembly output. The contents are
    verified to be identical to our current file contents."""
    runtime_addr = _check_addr("include_binary_file", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.include_binary_file(binary_loc.binary_addr, relative_filepath)

def go(print_output=True, post_trace_steps=None, autostring_min_length=3):
    """
    Classifies code and data, calculates labels and emits assembly.
    """

    # Once we start tracing, we're taking a "static" view of the code and we
    # don't want any leftover user hints about how to convert runtime addresses
    # to binary addresses confusing things.
    if len(session.current().moves.active_move_ids) != 0:
        utils.die("go() can't be called inside a 'with move(...):' block")
    if not session.current().memory.load_ranges:
        utils.die("go(): nothing has been loaded to disassemble (use load() first)")
    if not utils.is_integer_type(autostring_min_length) or autostring_min_length < 2:
        utils.die("go(): autostring_min_length must be at least 2, not {0!r}".format(autostring_min_length))

    # Find entire binary range
    pydis_start, pydis_end = memorymanager.get_entire_load_range()

    # Create start and end labels
    disassembly.add_label(memorymanager.RuntimeAddr(int(pydis_start)), "pydis_start", is_autogenerated=True, move_id=movemanager.BASE_MOVE_ID, priority=1)
    disassembly.add_label(memorymanager.RuntimeAddr(int(pydis_end)), "pydis_end", is_autogenerated=True, move_id=movemanager.BASE_MOVE_ID)

    # Trace where code lives
    session.current().cpu.trace()

    # Make sure local label names don't clash (before label names are finalised)
    labelmanager.assign_local_label_output_names()

    # Choose the names of the labels used by instructions and data
    disassembly.fix_label_names()

    # Output all the references
    if config.get_label_references():
        session.current().cpu.add_references_comments()

    # Scan the binary for strings (or allow a user function to do it)
    # We do this after tracing so we have the classifications.
    if post_trace_steps is None:
        def post_trace_steps():
            classification.autostring(autostring_min_length)
    post_trace_steps()

    # Mark everything remaining as bytes
    classification.classify_leftovers()

    # Choose the names of the labels used by the data classified since the
    # names were first chosen above (e.g. strings), and by comments
    disassembly.fix_label_names(include_annotations=True)

    # Get the final assembly as a string
    result = disassembly.emit()

    # Write to a file if specified (with -o on the command line), otherwise
    # print it if wanted
    asm_filename = session.current().asm_filename
    if asm_filename:
        with open(asm_filename, 'w') as file:
            file.write(result)
    elif print_output:
        print(result)

    # Write the JSON, a symbol file and a cross-reference listing, if wanted
    # (with --json, --symbols and --xref on the command line)
    s = session.current()
    if s.json_filename or s.symbols_filename or s.xref_filename:
        import jsonoutput
        import symbols
        doc = jsonoutput.document()
        if s.json_filename:
            jsonoutput.write(s.json_filename, doc)
        if s.symbols_filename:
            symbols.write_symbols(s.symbols_filename, s.symbols_format, doc)
        if s.xref_filename:
            symbols.write_xref(s.xref_filename, doc)

    # Return assembly code as a string
    return result

def reset():
    """
    Reset py8dis to its initial state, ready to disassemble something else.

    Everything from earlier commands is forgotten: loaded data, moves, labels,
    constants, comments, classifications, entry points, subroutines, hooks
    and settings. The command line is read again to choose the assembler and
    the case of the output (unless use_command_line(False) has been called).
    """

    # A new session, with new settings and a new assembler object
    session.new_session()

    # Let other modules (e.g. acorn.py) reset themselves
    for hook in _reset_hooks:
        hook()

_reset_hooks = []

def add_reset_hook(hook):
    """
    Register a function to be called by reset().

    For a module that keeps its own state outside the session. (A module
    can instead keep its state in the session's 'extras', as acorn.py does,
    which needs no hook.)
    """
    _reset_hooks.append(hook)

def set_output_filename(filename):
    """Set the filename for the assembler to save the assembled binary to
    (for assemblers that support this, e.g. beebasm and acme)."""
    session.current().output_filename = filename
