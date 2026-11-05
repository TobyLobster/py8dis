"""
Commands

The commands that control files use: the API that docs/commands.md describes
for users (and README.md introduces). A control file starts with 'from
commands import *', which gives it every public name in this module: the
commands below; the make_...() functions for expressions (from maker.py);
Align, Format and BinaryAddrType for the commands' arguments; get_label() and
use_command_line(); 'memory' and 'memory_binary', for reading the loaded
data by runtime or binary address (see memorymanager.py); and the modules
imported here, such as config and session, so that a control file can use
e.g. config.set_hex_dump(False).

Most commands take a runtime address: where the code or data is when the
program runs. Where a program copies part of itself somewhere else before
running it (see move()), that's different from its binary address, where the
bytes are in the loaded data. Each command checks its arguments, stopping
with utils.die() and a message naming the command if they're wrong; converts
the runtime address to a binary location (a binary address and move ID) with
movemanager.r2b_checked(); and records what it's been told in the current
session (see session.py), through the module that deals with it:
memorymanager.py for the loaded data, movemanager.py for moves,
classification.py for data and expressions, disassembly.py for labels,
comments and constants, the CPU object (cpu.py) for entry points and hooks,
and trace.py for subroutines. Nothing is traced or output until go(), which
does the whole disassembly.

The commands, in the groups docs/commands.md uses (see it for the details):

    Loading      load(), load_prg(), load_atm(), load_apple_file(),
                 load_dos33_binary(), move(), include_binary_file()
    Code         entry(), nonentry(), wordentry(), code_ptr(),
                 rts_code_ptr(), hook_subroutine() (and the ready-made
                 hooks stringz_hook etc.), subroutine()
    Labels       label(), optional_label(), local_label(), expr_label(),
                 memory_region(), io_range(), addr(), get_label(),
                 set_label_maker_hook(), is_simple_name()
    Expressions  constant(), expr(), substitute_constants(), make_...()
    Data         byte(), word(), string(), stringterm(), stringcr(),
                 stringz(), stringhi(), stringhiz(), stringn(),
                 split_classification()
    Formats      char(), binary(), picture_binary(), decimal(),
                 hexadecimal(), uhex(), uint(), uint_no_hex(), sint(),
                 padded_uint(), set_formatter()
    Comments     comment(), formatted_comment(), no_automatic_comment(),
                 blank(), blank_once(), annotate()
    Memory       get_u8_binary(), get_u16_binary(), get_u16_be_binary(),
                 get_u8_runtime(), get_u16_runtime(), get_u16_be_runtime()
    Output       go(), reset(), add_reset_hook(), set_output_filename(),
                 is_assembler(), use_command_line()

auto_comment() and auto_expr() are for py8dis's own modules (e.g. acorn.py):
they add a comment or an expression that py8dis has made up itself, which
no_automatic_comment() can turn off.
"""

import memorymanager
import re as _re

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
import cpuz80

# The CPUs that load() and load_prg() accept, by name (in lower case: the
# name given is converted to lower case before it's looked up)
cpu_names = { "6502"  : cpu6502.Cpu6502,
              "65c02" : cpu65C02.Cpu65C02,
              "6510"  : cpu6510.Cpu6510,
              "8080"  : cpu8080.Cpu8080,
              "z80"   : cpuz80.CpuZ80,
            }

# For control files: memory_binary[addr] is the byte loaded at a binary
# address, and memory[addr] the byte at a runtime address (or None where
# nothing is loaded). These always use the current session's memory.
memory_binary = memorymanager.memory_binary
memory        = memorymanager.memory

# Checking the user's arguments. User input is checked with these (and
# utils.die()) rather than with 'assert', since 'python -O' removes asserts.
# The messages name the command and show the arguments, in the assembler's
# hex syntax where they could be addresses.
def _hex(value):
    """A number in the assembler's hex syntax, e.g. $1f or &1234, for
    messages."""
    return config.get_assembler().hex(value)

def _show(value):
    """Format a value for an error message: in hex if it could be an address."""
    if utils.is_integer_type(value) and value >= 0:
        return _hex(value)
    return repr(value)

def _check_address_range(command, addr, allow_end=False):
    """Stop with an error unless addr is an integer address in memory ($0000
    to $ffff). If allow_end is True then $10000 (just past the end of memory,
    e.g. the end of a range, or a label just after the program) is allowed."""
    top = 0x10000 if allow_end else 0xffff
    if not utils.is_integer_type(addr) or not (0 <= addr <= top):
        utils.die("{0}({1}): the address must be between {2} and {3}".format(command, _show(addr), config.get_assembler().hex4(0), _hex(top)))

def _check_addr(command, runtime_addr, allow_end=False):
    """Check a runtime address given by the user (see _check_address_range()),
    returning it as a RuntimeAddr."""
    _check_address_range(command, runtime_addr, allow_end)
    return memorymanager.RuntimeAddr(runtime_addr)

def _check_count(command, runtime_addr, n, arg_name="n"):
    """Check that n (a number of bytes, words etc) is a positive integer.
    'arg_name' is the argument's name, for the message (e.g. "cols")."""
    if not utils.is_integer_type(n) or n <= 0:
        utils.die("{0}({1}, ...): {2} must be a positive integer, not {3!r}".format(command, _show(runtime_addr), arg_name, n))

def _check_name(command, runtime_addr, name, allow_expression=True):
    """Check a label name given by the user: it must be a non-empty string.
    Unless allow_expression is False, the name can be an expression (e.g.
    'table+1') rather than a simple name (see disassembly.is_simple_name())."""
    if not isinstance(name, str) or name == "":
        utils.die("{0}({1}, {2!r}): the name must be a non-empty string".format(command, _show(runtime_addr), name))
    if not allow_expression and not disassembly.is_simple_name(name):
        utils.die("{0}({1}, {2!r}): this isn't a valid label name (a letter or underscore followed by letters, digits or underscores)".format(command, _show(runtime_addr), name))

def _as_text(name):
    """A label name or expression can be given as an expression made by e.g.
    make_add(). If so, it's converted to text (unless it refers to a label that
    isn't named yet), in the current assembler's syntax. Anything else is
    returned as it is. (An expression left as it is fails _check_name(),
    which wants a string.)"""
    if isinstance(name, expression.Expr) and not name.is_lazy():
        return str(name)
    return name

def _check_move_id(command, runtime_addr, move_id):
    """Check a move_id given by the user: one returned by move(), or None."""
    if move_id is not None and not (utils.is_integer_type(move_id) and movemanager.is_valid_move_id(move_id)):
        utils.die("{0}({1}, ...): move_id must be a value returned by move(), not {2!r}".format(command, _show(runtime_addr), move_id))

def _check_in_memory(command, runtime_addr, binary_addr, n=1, count=None):
    """Stop with an error if the n bytes from binary_addr run past the top of
    memory. 'count' is the count the user gave, if different from n (e.g. a
    number of words), for the message."""
    if binary_addr + n > 0x10000:
        utils.die("{0}({1}, {2}): this runs past the top of memory".format(command, _hex(runtime_addr), n if count is None else count))

def _check_data_loaded(command, runtime_addr, binary_addr, n=1):
    """Stop with an error unless there is data loaded at all n bytes from binary_addr."""
    _check_in_memory(command, runtime_addr, binary_addr, n)
    if not memorymanager.is_data_loaded_at_binary_addr(binary_addr, n):
        utils.die("{0}({1}): no data is loaded at this address ({2})".format(command, _hex(runtime_addr), memorymanager.describe_loaded_files()))

def _cpu(command):
    """The session's CPU, which load() chooses: stops with an error if load()
    hasn't been called yet (for the commands that give the CPU entry points
    or hooks)."""
    cpu = session.current().cpu
    if cpu is None:
        utils.die("{0}(): call load() first (it chooses the CPU)".format(command))
    return cpu

def _binary_addr(binary_addr):
    """A binary address given by the user (already checked), as a
    BinaryAddr. It's converted from a plain int first, as it may be a
    RuntimeAddr a command returned (e.g. stringhi()'s), which with no moves is
    the same address."""
    return memorymanager.BinaryAddr(int(binary_addr))

# Reading the binary. (These check the user's address, then use the
# memorymanager functions of the same name. Each stops with an error if
# nothing is loaded at the bytes it reads. The _runtime ones convert the
# runtime address to a binary address first, through the moves: a hook is
# given runtime addresses, so it uses those.)
def get_u8_binary(binary_addr):
    """Read a single byte of data from the specified binary address."""
    _check_address_range("get_u8_binary", binary_addr)
    _check_data_loaded("get_u8_binary", binary_addr, binary_addr, 1)
    return memorymanager.get_u8_binary(_binary_addr(binary_addr))

def get_u16_binary(binary_addr):
    """Read a 16 bit value (little endian) from the specified binary address."""
    _check_address_range("get_u16_binary", binary_addr)
    _check_data_loaded("get_u16_binary", binary_addr, binary_addr, 2)
    return memorymanager.get_u16_binary(_binary_addr(binary_addr))

def get_u16_be_binary(binary_addr):
    """Read a 16 bit value (big endian) from the specified binary address."""
    _check_address_range("get_u16_be_binary", binary_addr)
    _check_data_loaded("get_u16_be_binary", binary_addr, binary_addr, 2)
    return memorymanager.get_u16_be_binary(_binary_addr(binary_addr))

def get_u8_runtime(runtime_addr):
    """Read a single byte of data from the specified runtime address."""
    runtime_addr = _check_addr("get_u8_runtime", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_data_loaded("get_u8_runtime", runtime_addr, binary_loc.binary_addr, 1)
    return memorymanager.get_u8_binary(binary_loc.binary_addr)

def get_u16_runtime(runtime_addr):
    """Read a 16 bit value (little endian) from the specified runtime address."""
    runtime_addr = _check_addr("get_u16_runtime", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    _check_data_loaded("get_u16_runtime", runtime_addr, binary_loc.binary_addr, 2)
    return memorymanager.get_u16_binary(binary_loc.binary_addr)

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
    file).

    'cpu_name' chooses the CPU (see _select_cpu()): a name such as "6502" or
    "Z80" (see cpu_names), or a Cpu object. Several files can be loaded, at
    different addresses, but all with the same CPU. The data goes into the
    session's memory (see memorymanager.load(), which reads the file and
    checks the md5sum). Stops with an error if the arguments are wrong, the
    file can't be read, or the data runs past the top of memory; warns if
    the file looks like a PRG, ATM or AppleSingle file loaded from its start
    (see load_prg(), load_atm() and load_apple_file()), or if it replaces
    data loaded earlier. See docs/commands.md."""

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
    # An ATM file's first 22 bytes are its header
    if offset == 0 and filename.lower().endswith(".atm"):
        utils.warn("{0}: this looks like an Acorn Atom ATM file, whose first 22 bytes are a header (its name, addresses and length), not data; load_atm({1!r}) loads it at its load address without them".format(command, filename))
    # An AppleSingle file starts with a header
    if offset == 0 and _file_start(filename, 4) == memorymanager.AppleSingleHeader.MAGIC.to_bytes(4, "big"):
        utils.warn("{0}: this is an AppleSingle file, which starts with a header (its parts and their file information), not data; load_apple_file({1!r}) loads its data at its load address".format(command, filename))

    memorymanager.load(filename, binary_load_addr, md5sum, offset, length, command=command)

def _file_start(filename, length):
    """The first 'length' bytes of a file, or None if it can't be read (for
    load()'s warnings; reading it properly reports any problem)."""
    try:
        with open(filename, "rb") as f:
            return f.read(length)
    except OSError:
        return None

def load_prg(filename, cpu_name="6502", md5sum=None):
    """Loads a Commodore PRG file: its first two bytes are the address to load
    the rest of it at. (A PC64 'P00' file, a PRG file after a 26 byte header
    starting 'C64File', is also accepted.)

    The disassembly starts with the same two bytes, so that it assembles to
    the whole PRG file. (To load the data without them, use
    load(address, filename, offset=2).) The md5sum, if given, is that of the
    whole file. Returns the load address.

    The file is loaded as a PRG file (see memorymanager.LoadedFile), which
    is what makes the output start with the two bytes (see
    memorymanager.file_header()). Stops with an error if the file is too
    short to be a PRG file."""

    command = "load_prg({0!r})".format(filename)
    def die(problem):
        """Stop with an error about the file, naming the command."""
        utils.die("{0}: {1}".format(command, problem))
    _select_cpu(cpu_name)

    # Read the load address from the file (after the P00 header, if there is
    # one), then load the rest of the file there
    data = memorymanager.read_file(filename, die)
    header_length = 26 if data[:8] == b"C64File\0" else 0
    if len(data) < header_length + 3:
        die("the file ({0} bytes) is too short to be a PRG file (two bytes of load address, then the data)".format(len(data)))
    binary_load_addr = data[header_length] | (data[header_length + 1] << 8)
    memorymanager.load(filename, binary_load_addr, md5sum, header_length + 2, prg=True, command=command)
    return binary_load_addr

def load_atm(filename, cpu_name="6502", md5sum=None):
    """Loads an Acorn Atom ATM file (the format of the Atom's emulators and
    its AtoMMC card): a 22-byte header (the file's name, in 16 bytes padded
    with zeroes; then its load address, execution address and length, each
    a word), then the data, which is loaded at the load address. If the
    execution address is in the data, it's traced (see entry()), with a
    comment, but without a name (give it one with label() or entry()).
    Returns the load address.

    The disassembly starts with the header, so that it assembles to the
    whole ATM file. (To load the data without it, use load(address,
    filename, offset=22).) The md5sum, if given, is that of the whole file.

    The file is loaded with its header (see memorymanager.LoadedFile and
    AtmHeader), which is what makes the output start with it (see
    memorymanager.file_header()). Stops with an error if the file is too
    short to be an ATM file; warns if the length in the header isn't the
    length of the data after it (all of which is loaded)."""

    command = "load_atm({0!r})".format(filename)
    def die(problem):
        """Stop with an error about the file, naming the command."""
        utils.die("{0}: {1}".format(command, problem))
    _select_cpu(cpu_name)

    data = memorymanager.read_file(filename, die)
    header_length = memorymanager.AtmHeader.LENGTH
    if len(data) < header_length + 1:
        die("the file ({0} bytes) is too short to be an ATM file (a 22-byte header, then the data)".format(len(data)))
    atm = memorymanager.AtmHeader(data)
    data_length = len(data) - header_length
    if atm.length != data_length:
        utils.warn("{0}: the header says the data is {1} bytes long, but there are {2} bytes after it (all of which are loaded)".format(command, atm.length, data_length))
    memorymanager.load(filename, atm.load_addr, md5sum, header_length, header=atm, command=command)

    # Trace the code at the execution address, if it's in the data, with a
    # comment saying it's where the file is run from (an automatic comment,
    # so no_automatic_comment() leaves it out)
    if atm.load_addr <= atm.exec_addr < atm.load_addr + data_length:
        entry(atm.exec_addr)
        auto_comment(atm.exec_addr, "The ATM file's execution address")
    return atm.load_addr

def _apple_load_addr(file_type, aux_type, die, use_load):
    """The address an Apple II file with the given ProDOS file type and aux
    type is loaded at: the aux type for a BIN file ($06) or an Applesoft
    program ($FC), and $2000 for a SYS file ($FF). For another type, 'die'
    is called, with 'use_load' (how to load the file with load()) in the
    message."""
    fmt = config.get_assembler()
    if file_type in (0x06, 0xfc, 0xff):
        load_addr = 0x2000 if file_type == 0xff else aux_type
        if load_addr <= 0xffff:
            return load_addr
        die("its aux type ({0}) isn't an address, so its load address isn't known: {1}".format(_hex(aux_type), use_load))
    die("its ProDOS file type is {0}, so its load address isn't known (only BIN, BAS and SYS files have one): {1}".format(memorymanager.prodos_file_type(file_type, fmt), use_load))

def load_apple_file(filename, cpu_name="6502", md5sum=None):
    """Loads an Apple II file whose load address the file or its name gives:

    - an AppleSingle file (the format of cc65's Apple II programs, and of
      AppleCommander's -as option), recognised by its magic number. Its
      header's ProDOS file information gives the file type and aux type,
      and its data fork is loaded;
    - a file whose name ends with '#', then the ProDOS file type and aux
      type in hex (e.g. 'GAME#062000', as CiderPress and NuLib2 name the
      files they extract). The whole file is loaded.

    A BIN file ($06) or an Applesoft program ($FC) is loaded at its aux
    type, and a SYS file ($FF) at $2000, where ProDOS runs it from, so a SYS
    file is traced from there, with a comment. (A BIN file isn't traced,
    since it may be data: use entry().) Returns the load address.

    An AppleSingle file's disassembly starts with its header (everything
    before the data fork), so that it assembles to the whole file. (To load
    the data without it, use load(address, filename, offset=...).) The
    md5sum, if given, is that of the whole file.

    Stops with an error if the file is neither, if its type isn't one of
    those, or if its AppleSingle header is wrong. Warns if the data fork
    isn't at the end of the file (then the output assembles to the data
    without the header)."""

    command = "load_apple_file({0!r})".format(filename)
    def die(problem):
        """Stop with an error about the file, naming the command."""
        utils.die("{0}: {1}".format(command, problem))
    _select_cpu(cpu_name)

    data = memorymanager.read_file(filename, die)
    magic = memorymanager.AppleSingleHeader.magic(data)
    if magic == memorymanager.AppleSingleHeader.APPLEDOUBLE_MAGIC:
        die("this is an AppleDouble header file, which holds the file's information but not its data (that's in a file of its own)")
    if magic == memorymanager.AppleSingleHeader.MAGIC:
        header = memorymanager.AppleSingleHeader(data, die)
        use_load = "use load(address, {0!r}, offset={1}, length={2})".format(filename, header.data_offset, header.data_length)
        if header.file_type is None:
            die("the AppleSingle file has no ProDOS file information (entry ID 11), so its load address isn't known: " + use_load)
        load_addr = _apple_load_addr(header.file_type, header.aux_type, die, use_load)
        if header.data_fork_is_last():
            memorymanager.load(filename, load_addr, md5sum, header.data_offset, header=header, command=command)
        else:
            utils.warn("{0}: the data fork isn't at the end of the file, so the output assembles to the data without the AppleSingle header".format(command))
            memorymanager.load(filename, load_addr, md5sum, header.data_offset, header.data_length, command=command)
        file_type = header.file_type
    else:
        match = _re.search(r"#([0-9a-fA-F]{2})([0-9a-fA-F]{4})$", filename)
        if match is None:
            die("this isn't an AppleSingle file, and its name doesn't end with '#' and its ProDOS file type and aux type (e.g. 'GAME#062000'), so its load address isn't known: use load(address, {0!r})".format(filename))
        file_type, aux_type = int(match.group(1), 16), int(match.group(2), 16)
        load_addr = _apple_load_addr(file_type, aux_type, die, "use load(address, {0!r})".format(filename))
        memorymanager.load(filename, load_addr, md5sum, command=command)

    # ProDOS runs a SYS file from its start (an automatic comment, so
    # no_automatic_comment() leaves it out)
    if file_type == 0xff:
        entry(load_addr)
        auto_comment(load_addr, "ProDOS runs a SYS file from here")
    return load_addr

def load_dos33_binary(filename, cpu_name="6502", md5sum=None):
    """Loads an Apple II DOS 3.3 binary file with its 4-byte header, as it
    is on the disk: its load address and its length, each a word, then the
    data, which is loaded at the load address. Returns the load address.
    (The data isn't traced, since it may not be code: use entry().)

    The disassembly starts with the header, so that it assembles to the
    whole file. (To load the data without it, use load(address, filename,
    offset=4).) The md5sum, if given, is that of the whole file.

    Stops with an error if the file is too short; warns if the length in
    the header isn't the length of the data after it (all of which is
    loaded)."""

    command = "load_dos33_binary({0!r})".format(filename)
    def die(problem):
        """Stop with an error about the file, naming the command."""
        utils.die("{0}: {1}".format(command, problem))
    _select_cpu(cpu_name)

    data = memorymanager.read_file(filename, die)
    header_length = memorymanager.Dos33Header.LENGTH
    if len(data) < header_length + 1:
        die("the file ({0} bytes) is too short to be a DOS 3.3 binary file (a 4-byte header, the load address and length, then the data)".format(len(data)))
    header = memorymanager.Dos33Header(data)
    data_length = len(data) - header_length
    if header.length < data_length:
        utils.warn("{0}: the header says the data is {1} bytes long, but there are {2} bytes after it (all of which are loaded; load({3}, {4!r}, offset=4, length={1}) loads just the {1})".format(command, header.length, data_length, _hex(header.load_addr), filename))
    elif header.length > data_length:
        utils.warn("{0}: the header says the data is {1} bytes long, but there are only {2} bytes after it (all of which are loaded)".format(command, header.length, data_length))
    memorymanager.load(filename, header.load_addr, md5sum, header_length, header=header, command=command)
    return header.load_addr

def _select_cpu(cpu_name):
    """Check the CPU asked for by load() or load_prg() is supported by the
    chosen assembler, and make it the session's CPU (or check it's the same
    type as one chosen by an earlier load()).

    'cpu_name' is a name from cpu_names (in any case), or a Cpu object, which
    is used as it is (without the check that the assembler supports it).
    Stops with an error if the assembler doesn't support the CPU, the name
    is unknown, or it's a different CPU from an earlier load()'s. For the
    65C02, it also tells the assembler (see config.set_cmos())."""
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
    # about (see config.get_cmos())
    if isinstance(session.current().cpu, cpu65C02.Cpu65C02):
        config.set_cmos(True)

def move(dest_runtime_addr, src_binary_addr, length):
    """Indicates that a block of memory is copied at runtime.

    Often a block of code or data is moved (relocated) after loading
    but before being used at runtime. For example, BBC Micro games that
    load at &1900 may relocate bits or even all of themselves down to
    &0e00 before being used.

    This function specifies such a move, indicating that the runtime
    address is different from the loaded address for a block of memory:
    the 'length' bytes at binary address 'src_binary_addr' run at runtime
    address 'dest_runtime_addr'. This allows labels within the block to be
    properly defined by their runtime addresses.

    move()s should be called before accessing the relocated block.
    As a simple rule put any move() commands first, directly after
    load().

    Returns the move ID (see movemanager.add_move()), which some commands
    take, and which works with 'with': inside 'with move(...):', a runtime
    address that more than one move could mean is taken to be in this one.
    Several moves can have the same runtime addresses (e.g. banks of a
    cartridge, see "Banks" in docs/commands.md). Stops with an error if the
    length isn't positive, the block runs past the top of memory, its
    source and destination are the same, or any of its source isn't loaded.
    """

    memory_binary = session.current().memory.binary
    def describe():
        """The command with its arguments, e.g. 'move($0e00, $1900, 256)',
        for messages."""
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
    src_binary_addr = _binary_addr(src_binary_addr)
    return movemanager.add_move(dest_runtime_addr, src_binary_addr, length)

def constant(value, name, comment=None, *, align=Align.INLINE, format=Format.DEFAULT):
    """Give a name to a constant value for use in the assembly.

    These names can then be used in subsequent calls to expr().

    The constant is defined at the top of the output ('name = value'), with
    its value written as 'format' says (see format.py), and the comment, if
    any, placed by 'align'. A constant isn't used anywhere by itself: only
    where expr() (or substitute_constants()) writes its name. Defining the
    same name again with the same value does nothing; with a different value
    it stops with an error (see disassembly.add_constant()), as do arguments
    of the wrong type. See docs/commands.md.
    """
    def check(ok, problem):
        """Stop with an error about 'problem' unless 'ok'."""
        if not ok:
            utils.die("constant({0}, {1!r}): {2}".format(value, name, problem))
    check(isinstance(name, str) and name != "" and disassembly.is_simple_name(name), "the name must be a valid label name (a letter or underscore followed by letters, digits or underscores)")
    check(comment is None or isinstance(comment, str), "the comment must be a string, not {0!r}".format(comment))
    check(isinstance(align, Align), "align must be an Align value (e.g. Align.INLINE), not {0!r}".format(align))
    check(isinstance(format, Format), "format must be a Format value (e.g. Format.HEX), not {0!r}".format(format))

    disassembly.add_constant(value, name, comment, align, format)

def label(runtime_addr, name, move_id=None):
    """Define a label name for a runtime address.

    The label is always in the output, whether or not anything uses it, and
    the instructions and data that refer to the address use it. An address
    can have several names: all are defined, and references use the first
    (unless a local label applies, see local_label()). 'move_id' (from
    move()) says which move's copy of the address it is, for an address that
    more than one move puts data at; by default it's the move of the 'with'
    block the command is in, or the only move with that address. The name
    can be an expression, such as "table+1", or one made by e.g. make_add(),
    which makes this the same as expr_label(). $10000, just past the top of
    memory, can be labelled too."""
    _label("label", runtime_addr, name, move_id)

def _label(command, runtime_addr, name, move_id=None):
    """label() and expr_label(): check the arguments, and add the name (or
    expression) to the label for runtime_addr (see disassembly.add_label()).
    'command' names the command, for messages."""
    runtime_addr = _check_addr(command, runtime_addr, allow_end=True) # $10000 is valid for labels
    name = _as_text(name)
    _check_name(command, runtime_addr, name)
    _check_move_id(command, runtime_addr, move_id)
    if move_id is None:
        # Look up the associated binary address, just to get the best move_id
        # (the 'with' block's move, or the only one with this runtime
        # address). This is None if the address is in more than one move and
        # none of them is active: the name or expression then goes in the
        # base move (see Label.add_explicit_name() and add_expression()).
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

    This is label() with an expression for the name (see _label()). Unlike
    expr(), the expression isn't checked:
    py8dis doesn't work out its value, and no assertion is added to the
    output, so a wrong one gives output that assembles to a different
    program. Returns None."""

    return _label("expr_label", runtime_addr, s)

def io_range(start_addr, end_addr):
    """Say that memory from start_addr up to (but not including) end_addr is
    memory mapped I/O, where reading can have side effects (e.g.
    acknowledging an interrupt): so an instruction that reads it isn't taken
    to be redundant (see config.set_redundant_instruction_comments()).
    acorn.bbc() etc. and commodore.c64() etc. say this for their machines'
    I/O. The ranges are kept in the session's DisassemblyState.io_ranges.
    Stops with an error if the range is empty or outside memory."""
    _check_address_range("io_range", start_addr)
    _check_address_range("io_range", end_addr, allow_end=True)
    if end_addr <= start_addr:
        utils.die("io_range({0}, {1}): the end must be after the start".format(_hex(start_addr), _hex(end_addr)))
    session.current().disassembly.io_ranges.append((start_addr, end_addr))

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

    When two consecutive bytes share a label (e.g. `userv` and `userv+1`)
    then `base_runtime_addr` points to the first byte. The name can then be
    an expression, and the first byte must have an optional label of its
    own, given first; where the name is used, the first byte's label is
    defined too (see disassembly.label_maker()).

    This is how the machine modules (e.g. acorn.bbc()) name hundreds of OS
    addresses without filling the output with unused labels. An optional
    label isn't used where the address has a label given otherwise, or if
    its name is given to another address. With definable_inline=False the
    label is always defined at the top ('name = value') rather than where it
    is in the code. See disassembly.add_optional_label(), which stops with
    an error if the address already has a different optional label."""

    runtime_addr = _check_addr("optional_label", runtime_addr)
    name = _as_text(name)
    # (With a base address the name can be an expression, e.g. 'userv+1')
    _check_name("optional_label", runtime_addr, name, allow_expression=base_runtime_addr is not None)
    if base_runtime_addr is not None:
        base_runtime_addr = _check_addr("optional_label", base_runtime_addr)
    disassembly.add_optional_label(runtime_addr, name, base_addr=base_runtime_addr, definable_inline=definable_inline)

def local_label(runtime_addr, name, start_addr, end_addr, move_id=None):
    """Define a label name for a runtime address but only within a given
    memory range.

    The name is used where the address is referred to by the code from
    start_addr up to (but not including) end_addr, e.g. for a zero page
    location that one routine uses for its own purpose; elsewhere the
    address keeps its other name. The name must be a simple name, not an
    expression. If it's already used for another address, it's written with
    a suffix (see labelmanager.assign_local_label_output_names(), which go()
    calls). See docs/commands.md."""

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

    'instruction' is the instruction as text (e.g. "sta sprite_number" or
    "jsr sprite_plot"), 'reg' the register ('a', 'x' or 'y'), and
    'constants_dict' maps values to names or expressions. This is recorded
    (as a cpu6502.SubConst) and done after tracing, by
    Cpu6502.substitute_constants(), which uses what's known about the
    registers before each matching instruction to find where the value was
    loaded. 6502 only.

    `define_all_constants` has three possible values:
        None    - define no constants (the default)
        False   - define only the constants used
        True    - define all constants (those that are simple names, at once)
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

    How: the name is given with entry() (so the subroutine is traced), or,
    with is_entry_point=False, as an optional label. If the subroutine is in
    the loaded data, the header comment is added now, made from the title,
    description and the on_entry and on_exit registers, between the
    dividing lines (see config.set_subroutine_header()); it's an automatic
    comment, so no_automatic_comment() at the address leaves it out. Then
    the subroutine is recorded (trace.add_subroutine()), and after tracing
    the CPU calls the hook as hook(runtime_addr, state, subroutine) for each
    call to it, and for the code at its address (in the CPU's
    find_subroutine_calls()). See docs/commands.md for the arguments.
    """
    runtime_addr = _check_addr("subroutine", runtime_addr)
    _check_move_id("subroutine", runtime_addr, move_id)
    for (arg, value) in (("on_entry", on_entry), ("on_exit", on_exit)):
        if value is not None and not isinstance(value, dict):
            utils.die("subroutine({0}, ...): {1} must be a dictionary (e.g. {{'a': 'the value'}}), not {2!r}".format(_hex(runtime_addr), arg, value))
    if name is not None and len(name)>0:
        if is_entry_point:
            _cpu("subroutine")
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
            """Call the CPU's default_subroutine_hook(), if it has one."""
            default_hook = getattr(session.current().cpu, "default_subroutine_hook", None)
            if default_hook is not None:
                default_hook(runtime_addr, state, subroutine)

    runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    # if the subroutine is within the binary, output a header comment for it.
    if memorymanager.is_data_loaded_at_binary_addr(binary_loc.binary_addr):
        # Format a comment for the subroutine header: the top dividing line
        # (added even if there's no text below it), then the title,
        # description and registers (each part after the first starting with
        # a blank line), then the bottom dividing line if there was any text
        if config.get_subroutine_header() is not None:
            auto_comment(runtime_addr, config.get_subroutine_header(), word_wrap=False)
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
    """Where a comment goes, from a comment command's 'inline' and 'align'
    arguments: 'align' if it's given, otherwise Align.INLINE if 'inline' is
    True, or Align.BEFORE_LABEL if not. ('inline=True' is a shorter way of
    saying 'align=Align.INLINE'.) Stops with an error, naming 'command', if
    'align' isn't an Align value."""
    # If no 'align' value is specified, use the True/False 'inline' value
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

    'align' says where it goes (see _convert_inline_to_align_internal()):
    before or after the address's label, before or after its line, or at
    the end of the line. A standalone comment is word wrapped at the column
    set by config.set_word_wrap_comment_column() (unless word_wrap=False),
    and indented by 'indent' levels. The text can contain labels (e.g. from
    get_label()), whose names are filled in when it's output. Stops with an
    error if nothing is loaded at the address, or an argument has the wrong
    type. See docs/commands.md.
    """
    runtime_addr = _check_addr("comment", runtime_addr)
    _check_data_loaded("comment", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr)
    def check(ok, problem):
        """Stop with an error about 'problem' unless 'ok'."""
        if not ok:
            utils.die("comment({0}, ...): {1}".format(_hex(runtime_addr), problem))
    check(isinstance(inline, bool),    "inline must be True or False, not {0!r}".format(inline))
    check(isinstance(indent, int),     "indent must be an integer, not {0!r}".format(indent))
    check(isinstance(word_wrap, bool), "word_wrap must be True or False, not {0!r}".format(word_wrap))

    # Work out where the comment goes, from 'inline' and 'align'
    align = _convert_inline_to_align_internal(inline, align)

    disassembly.comment(runtime_addr, text, word_wrap=word_wrap, indent=indent, align=align, auto_generated=False)

def formatted_comment(runtime_addr, text, inline=False, align=None, indent=0):
    """Add a comment without word wrapping.

    The same as comment() with word_wrap=False, for text laid out by the
    user: each line of the text is a line of the comment."""
    runtime_addr = _check_addr("formatted_comment", runtime_addr)
    _check_data_loaded("formatted_comment", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr)

    # Work out where the comment goes, from 'inline' and 'align'
    align = _convert_inline_to_align_internal(inline, align, "formatted_comment")

    disassembly.comment(runtime_addr, text, word_wrap=False, indent=indent, align=align)

def no_automatic_comment(runtime_addr):
    """Inhibits the output of any automatically generated comment at the
    given address.

    This turns off the comments and expressions py8dis makes up itself at
    the address (e.g. on an OS call, or a subroutine's header comment), so
    that the user can write their own. It records the binary address in the
    session's TraceState.no_auto_comment_set, which auto_expr() and the
    functions that add py8dis's own comments and expressions
    (disassembly.comment_binary() and classification.add_expression())
    check. The user's own comments and expr()s at the address are still
    output."""
    runtime_addr = _check_addr("no_automatic_comment", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    session.current().trace.no_auto_comment_set.add(binary_loc.binary_addr)

def auto_comment(runtime_addr, text, inline=False, align=None, indent=0, show_blank=False, word_wrap=True):
    """For internal use only. Generates a comment if not inhibited.

    This is comment() for a comment py8dis has made up itself (e.g. on an OS
    call, in acorn.py): it's left out if no_automatic_comment() was given
    for the address, and nothing happens (without an error) if runtime_addr
    is None, or can't be converted to a binary address, or has no data
    loaded. With show_blank, a blank line goes before the comment (even if
    the comment itself is left out)."""

    if runtime_addr is None:
        return

    # Work out where the comment goes, from 'inline' and 'align'
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
    given address.

    The text is output as it is, so it must be something the assembler
    understands. 'align' says where it goes (see comment()), and 'priority'
    orders several things with the same 'align' at the same address (lower
    first, see utils.sorted_annotations()). With once_only, nothing is added
    if the same text has already been added there with annotate()."""

    runtime_addr = _check_addr("annotate", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    disassembly.annotate_binary(binary_loc, s, align=align, priority=priority, once_only=once_only)

def blank(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None):
    """Add a blank line at the address (see annotate())."""
    annotate(runtime_addr, "", align=align, priority=priority)

def blank_once(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None):
    """Add a blank line at the address, unless blank() or blank_once()
    already has."""
    annotate(runtime_addr, "", align=align, priority=priority, once_only=True)

def expr(runtime_addr, s, force=True):
    """Define a string expression for an address.

    A string expression is output at the given runtime address
    instead of a regular numerical value.

    An expression is a string containing labels, constants and/or other
    arithmetic calculations that the assembler can interpret. When the
    given address is reached, the regular output is replaced by the string
    expression.

    e.g. 'lda #$30' might be replaced by 'lda #>screen_address'

    Alternatively, a dictionary can be supplied with integer keys and
    string values. The byte found at the address is used as the key,
    and is replaced with the expression string value.

    'runtime_addr' is the address of the value itself (e.g. an instruction's
    operand), not of the instruction it's part of. The expression is kept in
    the session's Classifications.expressions, by binary address, and
    replaces any given before (unless force=False). It's checked when the
    output is made (see classification.get_expression()): py8dis stops with
    an error if it can work out the value and it's wrong, and otherwise an
    assertion at the end of the output makes the assembler check it. Stops
    with an error if nothing is loaded at the address, or the dictionary has
    no entry for the byte there. See docs/commands.md.
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
    """For internal use only. Called internally in order to generate an
    expression, such as 'end_address - start_address' etc.

    This is expr() for an expression py8dis has made up itself (e.g. in
    acorn.py): it's left out if no_automatic_comment() was given for the
    address, or if an expression is already there (e.g. the user's), and
    nothing happens if runtime_addr is None or has no data loaded. (Unlike
    auto_comment(), it stops with an error for a runtime address that more
    than one move could mean.)"""

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
    """Categorise a number of bytes at the given address as byte data.

    The n bytes are written as data (e.g. beebasm's 'equb'), 'cols' to a line
    (by default, as many as fit before the inline comment column). Stops
    with an error if they run past the top of memory or any of them is
    already classified; warns, and does nothing, if any of them isn't
    loaded. Returns None."""

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

def word(runtime_addr, n=1, cols=None):
    """Categorise a number of 16 bit words at the given address as word data.

    As byte(), for n words (2n bytes, low byte first), e.g. beebasm's
    'equw'."""

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

    The entry point is added to the CPU's list (Cpu.add_entry(), as an
    explicit entry point, i.e. one the user gave), so load() must have
    chosen the CPU already: it stops with an error otherwise. 'label', if
    given, names the address, as
    label() would. Warns if no data is loaded there (unless warn=False).
    Returns the address's label (from disassembly.get_label()), for use in
    an expression, e.g. by wordentry().
    """

    cpu = _cpu("entry")
    runtime_addr = _check_addr("entry", runtime_addr)
    if label is not None:
        _check_name("entry", runtime_addr, label)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    _is_loaded_else_warn("entry", runtime_addr, binary_loc.binary_addr, 1, "there is no code here to trace", warn)

    cpu.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, label, explicit=True)

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

    This works by marking the address as already traced (in the CPU's
    traced_entry_points), so tracing that reaches it goes no further. Like
    entry(), it needs load() to have chosen the CPU. Stops with an error if
    nothing is loaded at the address.
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

    Each word (16 bits, low byte first) is given to entry(), so the code
    there is traced, and is written as that code's label (with expr()).
    Returns the runtime address after the table.
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

    When tracing reaches a call to runtime_addr, the CPU calls
    hook(runtime_addr, call_addr), with runtime addresses, and carries on
    tracing at the address it returns (or nowhere, if it returns None).
    The hook can also mark data and add entry points. The subroutine itself
    is an explicit entry point named 'name' (see entry()). Warns if nothing
    is loaded at runtime_addr (unless warn=False, e.g. for a ROM routine).
    See docs/commands.md.
    """

    cpu = _cpu("hook_subroutine")
    runtime_addr = _check_addr("hook_subroutine", runtime_addr)
    _check_name("hook_subroutine", runtime_addr, name)
    _is_loaded_else_warn("hook_subroutine", runtime_addr, movemanager.r2b_checked(runtime_addr).binary_addr, 1,
        "there is no code here to trace (use warn=False for a subroutine outside the binary)", warn)
    cpu.hook_subroutine(runtime_addr, name, hook)

# The ready-made hooks for hook_subroutine(). Each is given the subroutine's
# address ('target') and the address of the call to it ('addr'), marks the
# string after the call (which must be 3 bytes long, e.g. a 6502 JSR or a Z80
# CALL), and returns the address after the string, where the code carries on.

def stringhi_hook(target, addr):
    """Mark a stringhi() string after the call, and carry on after it."""
    return stringhi(addr + 3)

def stringhiz_hook(target, addr):
    """Mark a stringhiz() string after the call, and carry on after it."""
    return stringhiz(addr + 3)

def stringcr_hook(target, addr):
    """Mark a stringcr() string after the call, and carry on after it."""
    return stringcr(addr + 3)

def stringz_hook(target, addr):
    """Mark a stringz() string after the call, and carry on after it."""
    return stringz(addr + 3)

def stringn_hook(target, addr):
    """Mark a stringn() string after the call, and carry on after it."""
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

    The code is at the stored value plus 'offset' (wrapping round at the
    top of memory), and is named 'label_name' if given. The bytes are
    written as an expression of the code's label: 'label-offset', as a word
    if the two bytes are next to each other (low byte first), otherwise as
    its low and high bytes. Returns the runtime address after the two bytes
    if they're next to each other (in either order), otherwise None. Stops
    with an error if either byte isn't loaded.
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
    # 'rts' jump table entry of $ffff means the code is at $0000)
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
    executing 'rts'. (The 6502's RTS adds one to the address it pulls from
    the stack, so the table holds each routine's address minus one.)
    """
    return code_ptr(runtime_addr, runtime_addr_high, offset=1)

def set_label_maker_hook(hook):
    """
    Sets a user defined 'hook' function that can make label names.

    The hook is called once for each place a label is used or defined, with
    a LabelMakingData (see labelmakingdata.py) holding the address, where
    it's used, and the name py8dis suggests, and it can change the name
    (e.g. with its replace() method); see docs/snippets-and-hooks.md. (A
    hook that doesn't take just one parameter is called the older way:
    given the runtime address, the binary address and a (name, move_id)
    tuple, it returns a new name, a new tuple, or the suggestion unchanged.
    See disassembly._label_maker().)

    Sometimes having a routine to make label names can be useful. For
    example, labels at addresses that just 'rts' to early out of a
    subroutine can be labelled uniformly as 'return1', 'return2' etc.
    (py8dis does this itself, as 'return_1' etc., see
    config.set_label_return_instructions_numerically()), or a label can be
    renamed where it's used for something else in one part of the program.

    It can only be set once: a second call stops with an error.
    """

    if session.current().disassembly.user_label_maker_hook is not None:
        utils.die("set_label_maker_hook() can only be called once")
    disassembly.set_user_label_maker_hook(hook)

def addr(label_name):
    """Returns the runtime address of the given label name

    The name is looked for among the labels' names so far (e.g. given with
    label() or entry()) and the local labels' names, but not the optional
    labels' (see labelmanager.addr()). Returns None if there's no such
    label, or label_name isn't a string."""

    if not utils.is_string_type(label_name):
        return None

    return labelmanager.addr(label_name)

def set_formatter(runtime_addr, n, formatter):
    """
    Specifies a function used to format data in a block.

    The 'formatter' is a function that given a value to format, returns
    a string. It's called as formatter(value, bits), where 'bits' is 8 for
    a byte or 16 for a word, for the data values and the instructions'
    immediate values in the n bytes from runtime_addr (where no expression
    is given, see classification.get_constant8()). (For a word, the
    formatter at its first byte is used.)

    This function is used by the following formatting functions.
    (They use _set_formatter(), with py8dis's own formatters from
    mainformatter.py.)
    """

    _set_formatter("set_formatter", runtime_addr, n, formatter)

def _set_formatter(command, runtime_addr, n, formatter):
    """set_formatter() and the commands like it: record 'formatter' for each
    of the n bytes from runtime_addr, by binary address, in the session's
    DisassemblyState.format_hint. 'command' names the command, for
    messages."""
    runtime_addr = _check_addr(command, runtime_addr)
    _check_count(command, runtime_addr, n)
    _check_address_range(command, runtime_addr + n - 1)
    for i in range(n):
        binary_loc = movemanager.r2b_checked(runtime_addr + i)
        session.current().disassembly.format_hint[binary_loc.binary_addr] = formatter

def uhex(runtime_addr, n=1):
    """Specifies unsigned hex formatting for data in the given block: always
    2 digits for a byte and 4 for a word"""

    _set_formatter("uhex", runtime_addr, n, mainformatter.uhex_formatter)

def uint(runtime_addr, n=1):
    """Specifies unsigned decimal/hex formatting for data in the given block:
    decimal for a single digit, otherwise hex"""

    # This is nearly the default behaviour, but by specifying a formatter explicitly the
    # automatic addition of a comment showing the corresponding character for
    # immediate constants will be disabled for this address (see
    # config.set_show_char_literals()).
    _set_formatter("uint", runtime_addr, n, mainformatter.uint_formatter)

def uint_no_hex(runtime_addr, n=1):
    """Specifies unsigned decimal integer formatting for data in the given block"""

    _set_formatter("uint_no_hex", runtime_addr, n, mainformatter.uint_no_hex_formatter)

def sint(runtime_addr, n=1):
    """Specifies signed decimal formatting for data in the given block (or
    unsigned, for an assembler that can't take negative data, see
    mainformatter.sint_formatter())"""

    _set_formatter("sint", runtime_addr, n, mainformatter.sint_formatter)

def padded_uint(runtime_addr, n=1):
    """Specifies padded uint formatting for data in the given block: as
    uint(), padded with spaces so that columns of data line up"""

    _set_formatter("padded_uint", runtime_addr, n, lambda n, bits: mainformatter.uint_formatter(n, bits, pad=True))

def char(runtime_addr, n=1):
    """Specifies quoted character formatting for data in the given block,
    e.g. 'a' (in the session's text encoding, see
    config.set_text_encoding()). A value the assembler can't write as a
    character is written as uint() would."""

    _set_formatter("char", runtime_addr, n, mainformatter.char_formatter)

def binary(runtime_addr, n=1):
    """Specifies binary formatting for data in the given block, e.g.
    %01011011 (8 digits for a byte, 16 for a word)"""

    _set_formatter("binary", runtime_addr, n, mainformatter.binary_formatter)

def picture_binary(runtime_addr, n=1):
    """Specifies picture binary formatting for data in the given block, e.g.
    %#.##.##. for graphics, where the assembler can write it (otherwise as
    binary())"""

    _set_formatter("picture_binary", runtime_addr, n, mainformatter.picture_binary_formatter)

def decimal(runtime_addr, n=1):
    """Specifies decimal formatting for data in the given block"""

    _set_formatter("decimal", runtime_addr, n, mainformatter.decimal_formatter)

# "hex" is a Python built-in function so we can't use that.
def hexadecimal(runtime_addr, n=1):
    """Specifies hex formatting for data in the given block: 2 digits for a
    value under $100, otherwise 4"""

    _set_formatter("hexadecimal", runtime_addr, n, mainformatter.hexadecimal_formatter)

def is_assembler(s):
    """True if the output is for the assembler named 's' (in any case),
    e.g. is_assembler("acme"), for a control file that does something
    different for one assembler. The names are those of the command line
    options, e.g. "64tass" and "z88dk"."""
    if config.get_assembler().get_name().lower() == s.lower():
        return True
    return False

##############################################################################
# String functions
#
# Each marks a string at a runtime address (as a classification.String, see
# the *_binary() functions in classification.py, which do the work), and
# returns the runtime address after it, so that several in a row can be
# marked. Each stops with an error if nothing is loaded at the start, or the
# start is already classified (e.g. by an earlier byte() or string command).
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

    With n=None, the string ends at the first byte that isn't printable in
    its encoding, or at the end of the loaded data, or at something already
    classified. With n given, it stops with an error if any of the n bytes
    isn't loaded or is already classified.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("string", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)

    return classification.string_binary(binary_loc.binary_addr, n=n, encoding=_encoding(encoding))

def stringterm(runtime_addr, terminator, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by a given
    terminator byte.

    The terminator is part of the string, unless exclude_terminator is True,
    when it's left unclassified (so it becomes a byte of data, unless
    something else classifies it). Either way, the address returned is
    after the terminator. Stops with an error if there's no terminator
    before the end of the loaded data or something already classified.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringterm", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringterm_binary(binary_loc.binary_addr, terminator=terminator, exclude_terminator=exclude_terminator, encoding=_encoding(encoding))

def stringcr(runtime_addr, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by ASCII 13.

    (The same as stringterm() with 13, a carriage return, as the
    terminator.)

    Returns the next available memory address after the string."""

    return stringterm(runtime_addr, 13, exclude_terminator, encoding=encoding)

def stringz(runtime_addr, exclude_terminator=False, *, encoding=None):
    """Classifies part of the binary as a string followed by ASCII 0.

    (The same as stringterm() with 0 as the terminator.)

    Returns the next available memory address after the string."""

    return stringterm(runtime_addr, 0, exclude_terminator, encoding=encoding)

def stringhi(runtime_addr, include_terminator_fn=None, *, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set character.

    The character with bit 7 set can be the last character of the string
    (e.g. "HELLO" with the O's bit 7 set) or something else that follows
    it. include_terminator_fn is given that byte and says whether it's part
    of the string; if it is, it's written as e.g. $80+'O' (in the
    assembler's syntax). By default it isn't, and the string ends before
    it. The string also ends at the end of the loaded data, or at something
    already classified.

    In the Apple II's high ASCII (the "apple" encoding), whose characters
    all have bit 7 set, it's the other way round: the string ends at a
    character with bit 7 clear (written as a number, if it's included).

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringhi", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringhi_binary(binary_loc.binary_addr, include_terminator_fn=include_terminator_fn, encoding=_encoding(encoding))

def stringhiz(runtime_addr, include_terminator_fn=None, *, encoding=None):
    """Classifies a part of the binary as a string up to the next bit 7 set
    character or zero character.

    As stringhi(), except that a zero ends the string too, and the
    terminator, if include_terminator_fn says it's part of the string, is
    written as it is (not as e.g. $80+'O'). (In high ASCII, a zero has bit
    7 clear, so it ends the string as for stringhi().)

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringhiz", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringhiz_binary(binary_loc.binary_addr, include_terminator_fn=include_terminator_fn, encoding=_encoding(encoding))

def stringn(runtime_addr, *, encoding=None):
    """Classifies a part of the binary as a string with the first byte
    giving the length.

    The length byte is a byte of data, written as the difference between
    the labels at the end and start of the string (so it's still right if
    the string is changed). Stops with an error if the string runs past the
    loaded data or into something already classified.

    Returns the next available memory address after the string."""

    runtime_addr = _check_addr("stringn", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.stringn_binary(runtime_addr, binary_loc.binary_addr, encoding=_encoding(encoding))

#
# Other commands. (Assembler specific expression strings can be built using
# the make_...() functions, from maker.py, imported at the top of this file.)
#

def is_simple_name(s):
    """Check for a string being a single identifier (like 'start_of_table')
    vs a more complex expression like 'end_address - start_address'.

    A simple name is a letter or underscore followed by letters, digits or
    underscores. Anything that isn't a non-empty string (e.g. an expression
    made by make_add()) isn't one."""
    return isinstance(s, str) and s != "" and disassembly.is_simple_name(s)

def split_classification(runtime_addr):
    """Split a single classification into two at the given address. Allows
    partial strings to be shown on different lines of the output.

    The address is remembered (see classification.split_classification()),
    and anything classified later across it, e.g. by stringz() or by
    py8dis's own search for strings, is split there into two parts of the
    same kind. So this is best called before the data is classified: data
    already classified across the address is split into two blocks of bytes
    instead."""
    runtime_addr = _check_addr("split_classification", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    classification.split_classification(binary_loc.binary_addr, warn=False)

def include_binary_file(runtime_addr, relative_filepath):
    """Add an 'include binary' command in the assembly output. The contents are
    verified to be identical to our current file contents.

    The bytes at runtime_addr, as many as are in the file, are written as
    the assembler's directive for including a file (e.g. beebasm's
    'incbin'), with the path as given, relative to the folder py8dis is run
    from. They're classified as bytes, so py8dis doesn't look for strings
    in them. Stops with an error if the file can't be read, is empty, runs
    past the top of memory, differs from the loaded data, or covers data
    already classified (see classification.include_binary_file())."""
    runtime_addr = _check_addr("include_binary_file", runtime_addr)
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return classification.include_binary_file(binary_loc.binary_addr, relative_filepath)

def go(print_output=True, post_trace_steps=None, autostring_min_length=3):
    """
    Classifies code and data, calculates labels and emits assembly.

    This does the whole disassembly, from what the commands before it have
    recorded, so a control file calls it once, at the end. In order: it
    labels the start and end of the loaded data (pydis_start and
    pydis_end); traces the code from the entry points (Cpu.trace(), which
    also analyses the code and adds py8dis's own comments); chooses the
    labels' names; adds the comments saying where each label is used from;
    finds strings in the data that's left (or calls post_trace_steps()
    instead, if given); makes everything still unclassified into bytes; and
    makes the output (disassembly.emit()).

    The output is written to the file given with -o on the command line
    (asm_filename), or else printed, unless print_output is False. The JSON,
    symbol file and cross-reference listing are written too, if asked for.
    Returns the output as a string.

    autostring_min_length is the shortest run of printable characters taken
    to be a string. Stops with an error if it's less than 2, if nothing has
    been loaded, or if go() is called inside a 'with move(...):' block.
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

    # Zero page labels used by zero page instructions before they'd be defined
    # inline are defined at the top instead
    disassembly.define_forward_zero_page_labels_first()

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
            """The usual search for strings."""
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

    It does this by starting a new session (session.new_session(), with no
    options, so those of a session made with options of its own aren't kept:
    without the command line, they're the defaults), then calling the
    functions registered with add_reset_hook().
    """

    # A new session, with new settings and a new assembler object
    session.new_session()

    # Let other modules (e.g. acorn.py) reset themselves
    for hook in _reset_hooks:
        hook()

# The functions for reset() to call (see add_reset_hook()). These aren't part
# of the session, so they're kept by reset().
_reset_hooks = []

def add_reset_hook(hook):
    """
    Register a function to be called by reset().

    For a module that keeps its own state outside the session. (A module
    can instead keep its state in the session's 'extras', as acorn.py does,
    which needs no hook.) The hook is called with no arguments, after the
    new session has been made.
    """
    _reset_hooks.append(hook)

def set_output_filename(filename):
    """Set the filename for the assembler to save the assembled binary to
    (for assemblers that support this: beebasm's 'save', Baron's section
    'filename' and acme's '!to'). It's kept in the session's
    'output_filename', which those assemblers' output reads."""
    session.current().output_filename = filename
