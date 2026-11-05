"""
Memory Manager

Loads the binary data to disassemble into memory, and gives access to that
memory. It also defines the types py8dis uses for addresses, which the rest
of py8dis depends on.

Each session (see session.py) has 64K of memory, a Memory object. load()
puts a file's bytes there (for the load() and load_prg() commands in
commands.py), at their 'binary address': where the bytes are when the file
is loaded. A byte that nothing is loaded at is None.

A program can copy part of itself somewhere else before running it. A
'move' (see move() in docs/commands.md, and movemanager.py) says so, and
then a byte also has a 'runtime address': where it is when the code runs.
Without any moves, the two are the same. Each move has a 'move ID' (0 for
the base move: the bytes that aren't moved). Every binary address is in
exactly one move, so it has one runtime address; but several moves can put
bytes at the same runtime address (e.g. the banks of a cartridge, which all
run at the same address), so a runtime address can have more than one binary
address. movemanager.b2r() and r2b() convert between them.

The memory, classifications (see classification.py) and expressions are
kept by binary address; labels, and the addresses users give most commands,
are by runtime address.

The main pieces:

BinaryAddr, RuntimeAddr  ints that say which kind of address they are, so
                         that mixing the two up is caught by an assertion.
BinaryLocation           a binary address with a move ID, which says which
                         move's runtime address it stands for. Annotations
                         and references are kept by BinaryLocation.
get_u8_binary() etc.     read a byte or a word, by binary or runtime
                         address.
memory, memory_binary    for control files: memory[runtime_addr] and
                         memory_binary[binary_addr].
load()                   loads (part of) a file at a binary address.
"""

import session
import utils

# We make one class to hold a runtime address, and another for a binary address.
# They are just integers underneath, but storing them in classes means we can
# check they are of the correct type: making a BinaryAddr from a RuntimeAddr,
# or a RuntimeAddr from a BinaryAddr, is an assertion error. (A plain int can
# be made into either. Some functions, e.g. movemanager.b2r() and r2b(), insist
# on the right type, rather than a plain int.)
#
# Adding to one keeps its type (e.g. BinaryAddr + 1 is a BinaryAddr), but any
# other arithmetic, e.g. subtracting, or 1 + BinaryAddr, gives a plain int.
#
# (These are created very often, so they are written to be quick: no
# per-instance __dict__, and no super() calls.)
class BinaryAddr(int):
    """A binary address: where a byte is in py8dis's memory, i.e. where it is
    when the file is loaded (see the module docs)."""
    __slots__ = ()

    def __new__(cls, value):
        # (A runtime address is converted with movemanager.r2b() instead)
        assert not isinstance(value, RuntimeAddr)
        return int.__new__(cls, value)

    def __add__(self, other):
        return BinaryAddr(int.__add__(self, other))

class RuntimeAddr(int):
    """A runtime address: where a byte is when the code runs, after any moves
    (see the module docs)."""
    __slots__ = ()

    def __new__(cls, value):
        # (A binary address is converted with movemanager.b2r() instead)
        assert not isinstance(value, BinaryAddr)
        return int.__new__(cls, value)

    def __add__(self, other):
        return RuntimeAddr(int.__add__(self, other))

# Address validation
def is_valid_runtime_addr(runtime_addr, allow_final_address = False):
    """True if runtime_addr is in memory, i.e. &0000-&ffff.

    With 'allow_final_address', &10000, the address just past the top of
    memory, is valid too: e.g. for the end of a range, or a label just after
    the last byte. (Passing a BinaryAddr is an assertion error.)"""

    assert not isinstance(runtime_addr, BinaryAddr)
    if allow_final_address:
        return 0 <= runtime_addr <= 0x10000
    return 0 <= runtime_addr < 0x10000

def is_valid_binary_addr(binary_addr, allow_final_address = False):
    """True if binary_addr is in memory, i.e. &0000-&ffff (or &10000 too,
    with 'allow_final_address'), as is_valid_runtime_addr(). (Passing a
    RuntimeAddr is an assertion error.)"""

    assert not isinstance(binary_addr, RuntimeAddr)
    if allow_final_address:
        return 0 <= binary_addr <= 0x10000
    return 0 <= binary_addr < 0x10000


# Memory access by binary address
#
# (These are for py8dis itself: it's an assertion error if nothing is loaded
# there. The commands of the same names in commands.py check the address
# for control files, and stop with a proper error.)
def get_u8_binary(binary_addr):
    """The byte at a binary address."""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None, "Bad address {0}".format(hex(binary_addr))
    return memory_binary[binary_addr]

def get_u16_binary(binary_addr):
    """The 16 bit number (little-endian: low byte first) at a binary
    address."""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None, "Nothing loaded at address {0}".format(hex(binary_addr))
    assert memory_binary[binary_addr+1] is not None, "Nothing loaded at address {0} (supposed 2nd byte of 16 bit address)".format(hex(binary_addr+1))
    return memory_binary[binary_addr] + (memory_binary[binary_addr+1] << 8)

def get_u16_be_binary(binary_addr):
    """The 16 bit number (big-endian: high byte first) at a binary address."""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None and memory_binary[binary_addr+1] is not None
    return (memory_binary[binary_addr] << 8) | memory_binary[binary_addr+1]



# Memory access by runtime address
#
# (These convert the runtime address with movemanager.r2b_checked(), which
# stops with an error if more than one move puts a byte there and none of them
# is active. For a word, the second byte is the one after the first in the
# binary.)
def get_u8_runtime(runtime_addr):
    """The byte at a runtime address."""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u8_binary(binary_loc.binary_addr)

def get_u16_runtime(runtime_addr):
    """The 16 bit number (little-endian: low byte first) at a runtime
    address."""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u16_binary(binary_loc.binary_addr)

def get_u16_be_runtime(runtime_addr):
    """The 16 bit number (big-endian: high byte first) at a runtime
    address."""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u16_be_binary(binary_loc.binary_addr)

class BinaryLocation:
    """A binary address ('binary_addr', a BinaryAddr) and a move ID
    ('move_id'), which together say which runtime address is meant: the
    binary address's runtime address in that move (see
    movedefinition.MoveDefinition.convert_binary_to_runtime_addr()).

    Usually the move is the one the byte is in (see
    movemanager.Moves.move_id_for_binary_addr), but at either end of a moved
    block it can be another: e.g. a label for the address the block is
    loaded at is output just before the block, at the block's first binary
    address in the base move, while the labels inside the block are at its
    runtime addresses, in its own move. (movemanager.make_binloc() makes one
    from a plain binary address.)

    BinaryLocations are used as dictionary keys (e.g. for annotations, and
    for the references to labels), so two are equal when both the address
    and the move ID are. It's shown as e.g. '0x2000[1]' (or just '0x2000'
    in the base move)."""

    def __init__(self, binary_addr, move_id):
        assert binary_addr is not None
        assert move_id is not None
        self.binary_addr = BinaryAddr(binary_addr)
        self.move_id = move_id

    def __str__(self) -> str:
        result = hex(self.binary_addr)
        if self.move_id != 0:
            result += "[" + str(self.move_id) + "]"
        return result

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        """Equal if both the binary address and the move ID are."""
        if isinstance(other, BinaryLocation):
            return (self.binary_addr == other.binary_addr) and (self.move_id == other.move_id)
        return NotImplemented

    def __hash__(self):
        """A hash of the binary address and the move ID (to match __eq__)."""
        return hash((self.binary_addr, self.move_id))

class MemoryRuntime:
    """Reads the current session's memory by runtime address, with the
    address checked, for control files (see 'memory' below)."""

    def __getitem__(self, runtime_addr):
        """The byte at a runtime address, or None if nothing is loaded there.
        Stops with an error (utils.die()) if the address isn't an int in
        memory, or if more than one move puts a byte there and none of them
        is active (see movemanager.r2b_checked())."""
        import movemanager
        if not (isinstance(runtime_addr, int) and is_valid_runtime_addr(runtime_addr)):
            import config
            h = config.get_assembler().hex
            utils.die("memory[{0}]: the address must be between {1} and {2}".format(h(runtime_addr) if isinstance(runtime_addr, int) and runtime_addr >= 0 else repr(runtime_addr), config.get_assembler().hex4(0), h(0xffff)))
        runtime_addr = RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        return session.current().memory.binary[binary_loc.binary_addr]

class MemoryBinary:
    """Class for reading (and writing) the current session's memory by binary
    address, for control files (see 'memory_binary' below). It works as the
    session's Memory.binary list does, with no checks: a byte nothing is
    loaded at is None."""

    def __getitem__(self, binary_addr):
        return session.current().memory.binary[binary_addr]

    def __setitem__(self, binary_addr, value):
        session.current().memory.binary[binary_addr] = value

    def __len__(self):
        return len(session.current().memory.binary)

    def __iter__(self):
        return iter(session.current().memory.binary)

class Memory:
    """The memory of one session (see session.py), by binary address, and
    what's been loaded into it."""

    def __init__(self):
        # We store 64K of memory, as a list of 65536 bytes (ints), by binary
        # address. Some portion of this will hold the binary file(s) to
        # disassemble; the rest is None. The get_u*() functions above assert
        # that something is loaded where they read. (Code that reads a lot
        # uses this list directly, which is quicker.)
        self.binary = [None] * 64*1024

        # Stores a (start_binary_addr, end_binary_addr) pair for each load()
        # ('end' exclusive), in the order loaded. They can overlap: see
        # loaded_ranges().
        self.load_ranges = []

        # The files loaded, in the order loaded: a LoadedFile for each load()
        self.loaded_files = []

# The headers of the file formats whose loading commands make the output
# start with the header, so that it assembles to the whole file (see
# file_header()). Each has:
#
#   'what'           what it is, for messages and the output's comment, e.g.
#                    "ATM file's header"
#   'header_length'  its length in bytes (the data follows it)
#   fields(fmt)      its contents, as a list of (kind, values, comment): kind
#                    "bytes" or "words" (little-endian), the values, and what
#                    they are. 'fmt' is the assembler, for numbers in the
#                    comments. (See Assembler.header_lines().)
#   json()           what the JSON's entry for the load gains (see
#                    jsonoutput._loads()), e.g. {"atm": {...}}
#
# A PRG file's two-byte header is simpler, and LoadedFile.prg says it's one.

class AtmHeader:
    """The 22-byte header of an Acorn Atom ATM file (see load_atm()): its
    'name' (16 bytes, zero-padded), its 'load_addr' and 'exec_addr', and the
    'length' of the data it says follows."""

    LENGTH = 22
    what = "ATM file's header"
    header_length = LENGTH

    def __init__(self, data):
        """Read the header from the start of 'data' (the file's bytes)."""
        def word(offset):
            return data[offset] | (data[offset + 1] << 8)
        self.name = bytes(data[0:16])
        self.load_addr = word(16)
        self.exec_addr = word(18)
        self.length = word(20)

    def fields(self, fmt):
        """Its name's 16 bytes, then its load address, execution address and
        length."""
        shown = "".join(chr(c) if 32 <= c < 127 else "." for c in self.name.rstrip(b"\0"))
        return [("bytes", list(self.name), 'Name: "{0}"'.format(shown)),
                ("words", [self.load_addr], "Load address"),
                ("words", [self.exec_addr], "Execution address"),
                ("words", [self.length], "Length")]

    def json(self):
        """Its name and execution address."""
        return { "atm": { "name": self.name.rstrip(b"\0").decode("latin-1"), "exec": self.exec_addr } }

class Dos33Header:
    """The 4-byte header of an Apple II DOS 3.3 binary file (see
    load_dos33_binary()): its 'load_addr' and the 'length' of the data it
    says follows, each a little-endian word."""

    LENGTH = 4
    what = "DOS 3.3 file's header"
    header_length = LENGTH

    def __init__(self, data):
        """Read the header from the start of 'data' (the file's bytes)."""
        self.load_addr = data[0] | (data[1] << 8)
        self.length = data[2] | (data[3] << 8)

    def fields(self, fmt):
        """The load address and length."""
        return [("words", [self.load_addr], "Load address"),
                ("words", [self.length], "Length")]

    def json(self):
        """The length the header gives."""
        return { "dos33": { "length": self.length } }

# ProDOS's names for the file types py8dis mentions in messages
PRODOS_FILE_TYPES = { 0x04: "TXT", 0x06: "BIN", 0x0f: "DIR", 0xfa: "INT", 0xfc: "BAS", 0xfd: "VAR", 0xfe: "REL", 0xff: "SYS" }

def prodos_file_type(file_type, fmt):
    """A ProDOS file type for messages and comments, e.g. '$06 (BIN)', using
    the assembler 'fmt''s hex."""
    name = PRODOS_FILE_TYPES.get(file_type)
    return fmt.hex2(file_type) + (" ({0})".format(name) if name else "")

class AppleSingleHeader:
    """The header of an AppleSingle file (see load_apple_file()), version 1
    or 2: a magic number, the version, 16 bytes of filler (in version 1, the
    name of the file system the file came from), the number of entries, and
    an ID, offset and length for each entry (all big-endian). The entries
    are the file's parts: its data fork (ID 1), its real name (3), its
    ProDOS file information (11) and so on, each at its offset in the file.

    The header, for the output, is everything before the data fork, whose
    'data_offset' is its 'header_length'. 'name' is the real name (bytes, or
    None if there isn't one), and 'access', 'file_type' and 'aux_type' are
    from the ProDOS file information (None if there isn't any). 'entries' is
    a list of (ID, offset, length)."""

    MAGIC = 0x00051600
    APPLEDOUBLE_MAGIC = 0x00051607
    what = "AppleSingle file's header"

    # The entry IDs' meanings
    ENTRY_NAMES = { 1: "data fork", 2: "resource fork", 3: "real name", 4: "comment", 5: "black and white icon",
                    6: "colour icon", 8: "file dates", 9: "Finder info", 10: "Macintosh file info",
                    11: "ProDOS file info", 12: "MS-DOS file info", 13: "short name", 14: "AFP file info",
                    15: "directory ID" }

    @staticmethod
    def magic(data):
        """The magic number at the start of 'data', or None if it's too
        short."""
        return int.from_bytes(data[0:4], "big") if len(data) >= 4 else None

    def __init__(self, data, die):
        """Read the header of the AppleSingle file 'data' (its bytes, which
        start with the magic number). 'die' is called with a description of
        any problem."""
        def be(offset, length):
            return int.from_bytes(data[offset:offset + length], "big")
        self.data = bytes(data)
        if len(data) < 26:
            die("the file ({0} bytes) is too short to be an AppleSingle file (its header is at least 26 bytes)".format(len(data)))
        self.version = be(4, 4)
        if self.version not in (0x00010000, 0x00020000):
            die("this is an AppleSingle file of version {0:08x}, but py8dis only knows versions 1 and 2".format(self.version))
        count = be(24, 2)
        if len(data) < 26 + 12 * count:
            die("the file ({0} bytes) is too short for the AppleSingle header's {1} entries".format(len(data), count))
        self.entries = []
        for i in range(count):
            entry_id, offset, length = be(26 + 12 * i, 4), be(30 + 12 * i, 4), be(34 + 12 * i, 4)
            if offset + length > len(data):
                die("the AppleSingle header's entry {0} ({1}) runs past the end of the file ({2} bytes)".format(i + 1, self._entry_name(entry_id), len(data)))
            self.entries.append((entry_id, offset, length))
        self.entries_end = 26 + 12 * count

        data_forks = [(offset, length) for entry_id, offset, length in self.entries if entry_id == 1]
        if not data_forks:
            die("the AppleSingle file has no data fork")
        self.data_offset, self.data_length = data_forks[0]
        if self.data_length == 0:
            die("the AppleSingle file's data fork is empty")
        self.header_length = self.data_offset

        self.name = None
        self.access = self.file_type = self.aux_type = None
        for entry_id, offset, length in self.entries:
            if entry_id == 3:
                self.name = bytes(data[offset:offset + length])
            elif entry_id == 11 and length >= 8:
                self.access, self.file_type, self.aux_type = be(offset, 2), be(offset + 2, 2), be(offset + 4, 4)

    def data_fork_is_last(self):
        """True if the data fork is at the end of the file, after all of the
        header and the other entries, so the output can be the header then
        the data."""
        if self.data_offset + self.data_length != len(self.data) or self.data_offset < self.entries_end:
            return False
        return all(offset + length <= self.data_offset for entry_id, offset, length in self.entries if entry_id != 1)

    def _entry_name(self, entry_id):
        return self.ENTRY_NAMES.get(entry_id, "ID {0}".format(entry_id))

    def fields(self, fmt):
        """The header's fixed fields, its entries, then the entries' contents
        (other than the data fork's), in the order they're in the file, with
        any bytes between them that no entry uses. (Only when
        data_fork_is_last().)"""
        data = self.data
        def shown(text):
            return "".join(chr(c) if 32 <= c < 127 else "." for c in text)
        result = [("bytes", list(data[0:4]), "AppleSingle's magic number"),
                  ("bytes", list(data[4:8]), "Version {0}".format(self.version >> 16))]
        filler = data[8:24]
        if self.version == 0x00010000 and filler.rstrip(b" \0"):
            result.append(("bytes", list(filler), 'Home file system: "{0}"'.format(shown(filler.rstrip(b" \0")))))
        else:
            result.append(("bytes", list(filler), "Filler"))
        count = len(self.entries)
        result.append(("bytes", list(data[24:26]), "{0} entr{1}".format(count, "y" if count == 1 else "ies")))
        for i, (entry_id, offset, length) in enumerate(self.entries):
            result.append(("bytes", list(data[26 + 12 * i:38 + 12 * i]),
                           "Entry {0}: {1}, at offset {2}, {3} byte{4}".format(i + 1, self._entry_name(entry_id), offset, length, "" if length == 1 else "s")))

        # The entries' contents, other than the data fork's, in order
        addr = self.entries_end
        for entry_id, offset, length in sorted((e for e in self.entries if e[0] != 1), key=lambda e: e[1]):
            if length == 0:
                continue
            if offset > addr:
                result.append(("bytes", list(data[addr:offset]), "Not used"))
            content = data[offset:offset + length]
            if entry_id == 11 and length == 8:
                result.append(("bytes", list(content[0:2]), "Access: {0}".format(fmt.hex2(self.access))))
                result.append(("bytes", list(content[2:4]), "File type: {0}".format(prodos_file_type(self.file_type, fmt))))
                result.append(("bytes", list(content[4:8]), "Aux type: {0}".format(fmt.hex4_for_comment(self.aux_type))))
            elif entry_id == 3:
                result.append(("bytes", list(content), 'Real name: "{0}"'.format(shown(content))))
            else:
                result.append(("bytes", list(content), self._entry_name(entry_id)[0].upper() + self._entry_name(entry_id)[1:]))
            addr = offset + length
        if self.data_offset > addr:
            result.append(("bytes", list(data[addr:self.data_offset]), "Not used"))
        return result

    def json(self):
        """The real name, file type and aux type, if it has them."""
        result = {}
        if self.name is not None:
            result["name"] = self.name.decode("latin-1")
        if self.file_type is not None:
            result["file_type"] = self.file_type
            result["aux_type"] = self.aux_type
        return { "applesingle": result }

class LoadedFile:
    """A file loaded with load(), load_prg(), load_atm(), load_apple_file()
    or load_dos33_binary(): its filename (as given), and the binary
    addresses it's loaded at, from 'start' up to (but not including) 'end'.
    'offset' is where in the file the data loaded starts, 'prg' is True for
    a PRG file loaded with load_prg(), and 'header' is the header of a file
    whose output can start with it (AtmHeader, Dos33Header or
    AppleSingleHeader; or None)."""

    def __init__(self, filename, start, end, offset=0, prg=False, header=None):
        self.filename = filename
        self.start = start
        self.end = end
        self.offset = offset
        self.prg = prg
        self.header = header

    def describe(self):
        """e.g. "'orig/helloworld.orig' at &2000-&201b", for messages."""
        import config
        h = config.get_assembler().hex4
        from_offset = " (from offset {0})".format(self.offset) if self.offset else ""
        return "{0!r}{1} at {2}-{3}".format(self.filename, from_offset, h(self.start), h(self.end - 1))

def describe_loaded_files():
    """The files loaded, for messages, e.g. "data is loaded from
    'orig/helloworld.orig' at &2000-&201b"."""
    files = session.current().memory.loaded_files
    if not files:
        return "nothing is loaded"
    return "data is loaded from " + ", ".join(f.describe() for f in files)

# For control files (which get these with 'from commands import *'), and
# acorn.py: these always use the current session's memory.
#
# 'memory' reads memory by runtime address, with the address conversion and
# validation. (A more exact name would be memory_runtime, but control files
# already use 'memory', and it's the main way they read memory, so it has the
# short name.)
#
# 'memory_binary' reads memory by binary address. Code in py8dis itself uses
# session.current().memory.binary instead, which is quicker.
memory = MemoryRuntime()
memory_binary = MemoryBinary()

def loaded_ranges():
    """The binary address ranges holding loaded data, as a sorted list of
    (start, end) pairs of ints, with overlapping or adjacent ranges merged.

    Used to avoid looping over all 64K of memory when only part of it holds
    the binary being disassembled."""
    result = []
    for start, end in sorted((int(s), int(e)) for s, e in session.current().memory.load_ranges):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return result

def get_entire_load_range():
    """The binary address range from the lowest loaded byte to the highest,
    as (start, end), 'end' exclusive. (Any gaps between the files loaded are
    included.) go() puts the labels pydis_start and pydis_end there.

    Something must have been loaded: it fails (with a ValueError) if
    nothing has."""

    load_ranges = session.current().memory.load_ranges
    pydis_start = min(start_addr for start_addr, end_addr in load_ranges)
    pydis_end   = max(end_addr for start_addr, end_addr in load_ranges)

    return (pydis_start, pydis_end)

def read_file(filename, die):
    """The contents of a file, as a bytearray. 'die' is called with a
    description of any problem."""
    try:
        with open(filename, "rb") as f:
            return bytearray(f.read())
    except OSError as e:
        die("can't read the file ({0})".format(e.strerror))

def load(filename, binary_addr, md5sum=None, offset=0, length=None, *, prg=False, header=None, command=None):
    """Load a binary file (or the part of it from 'offset', for 'length'
    bytes or to the end) into memory at the given binary address. This does
    the work of the load(), load_prg(), load_atm(), load_apple_file() and
    load_dos33_binary() commands (in commands.py).

    Checks the md5 checksum (of the whole file) matches if given. 'command'
    describes the command for messages, e.g. "load(&2000, 'file')". 'prg'
    is True for load_prg(), and 'header' the file's header (an AtmHeader
    etc.) for the other commands that read one, so the output can start
    with it (see file_header()).

    Stops with an error (utils.die()) if the file can't be read, is empty,
    is shorter than 'offset' and 'length' need, doesn't match the md5sum,
    or runs past the top of memory. Warns if it replaces data loaded
    earlier. Records the load in Memory.load_ranges and
    Memory.loaded_files."""

    import config
    binary_addr = BinaryAddr(binary_addr)
    memory = session.current().memory
    h = config.get_assembler().hex4
    if command is None:
        command = "load({0}, {1!r})".format(h(binary_addr), filename)
    def die(problem):
        utils.die("{0}: {1}".format(command, problem))

    data = read_file(filename, die)
    if len(data) == 0:
        die("the file is empty")
    whole_file = (offset == 0 and length is None)
    if offset >= len(data):
        die("the offset ({0}) is past the end of the file ({1} bytes)".format(offset, len(data)))
    if length is not None and offset + length > len(data):
        die("the offset and length ({0} + {1}) run past the end of the file ({2} bytes)".format(offset, length, len(data)))

    if md5sum is not None:
        import hashlib
        actual = hashlib.md5(data).hexdigest()
        if md5sum != actual:
            die("the file's md5sum is {0}, not {1} as expected".format(actual, md5sum))

    data = data[offset:] if length is None else data[offset:offset + length]
    if binary_addr + len(data) > 0x10000:
        if whole_file:
            die("the file ({0} bytes) runs past the top of memory".format(len(data)))
        die("the {0} bytes loaded run past the top of memory".format(len(data)))

    # Loading over data loaded earlier replaces it. That's still allowed, but
    # it's probably a mistake, so py8dis warns
    end_addr = binary_addr + len(data)
    for earlier in memory.loaded_files:
        if earlier.start < end_addr and binary_addr < earlier.end:
            utils.warn("{0}: this replaces some of the data loaded from {1}".format(command, earlier.describe()))

    memory.binary[binary_addr:end_addr] = data
    memory.load_ranges.append((binary_addr, end_addr))
    memory.loaded_files.append(LoadedFile(filename, int(binary_addr), int(end_addr), offset, prg, header))

class FileHeader:
    """The header of a loaded file that the output starts with (see
    file_header()): the LoadedFile, the 'load_addr' its data is at, and the
    header's 'length' in bytes, which is just below it (2 for a PRG file,
    or its header's header_length)."""

    def __init__(self, loaded_file, length):
        self.loaded_file = loaded_file
        self.load_addr = int(loaded_file.start)
        self.length = length

def file_header():
    """If the output starts with the header of a file loaded with load_prg()
    (its two-byte load address), or with load_atm(), load_apple_file() or
    load_dos33_binary() (its LoadedFile.header), so that it assembles to the
    whole file, a FileHeader; otherwise None. That's when
    the file is loaded at the lowest address loaded, high enough for the
    header to fit below it. disassembly.emit(), beebasm.py and baron.py use
    this to output the header."""
    memory = session.current().memory
    if not memory.load_ranges:
        return None
    start, _ = get_entire_load_range()
    for loaded_file in memory.loaded_files:
        if loaded_file.start != start:
            continue
        length = 2 if loaded_file.prg else loaded_file.header.header_length if loaded_file.header is not None else 0
        if length and start >= length:
            return FileHeader(loaded_file, length)
    return None

def prg_header_addr():
    """If the output starts with a PRG file's two-byte load address (see
    load_prg() and file_header()), the load address; otherwise None."""
    header = file_header()
    if header is not None and header.loaded_file.prg:
        return header.load_addr
    return None

def is_data_loaded_at_binary_addr(binary_addr, n=1):
    """True if data is loaded at all the 'n' bytes from binary_addr. (They
    must all be in memory: it's an assertion error if they run past the top,
    so callers check that first.)"""
    assert all(is_valid_binary_addr(x) for x in range(binary_addr, binary_addr+n))
    memory_binary = session.current().memory.binary
    return all(memory_binary[binary_addr + i] is not None for i in range(n))

