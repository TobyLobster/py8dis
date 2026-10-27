"""
Memory Manager

Loads binary data into memory ready to disassemble, and provides access to this
memory.

Code can sometimes be assembled at one address (the 'binary address') but will
be executed at another (the 'runtime address'). We define classes that help
distinguish these types of addresses.
"""

import session
import utils

# We make one class to hold a runtime address, and another for a binary address.
# They are just integers underneath, but storing them in classes means we can
# check they are of the correct type.
#
# (These are created very often, so they are written to be quick: no
# per-instance __dict__, and no super() calls.)
class BinaryAddr(int):
    """Address of data at load time"""
    __slots__ = ()

    def __new__(cls, value):
        assert not isinstance(value, RuntimeAddr)
        return int.__new__(cls, value)

    def __add__(self, other):
        return BinaryAddr(int.__add__(self, other))

class RuntimeAddr(int):
    """Address of data at execution time"""
    __slots__ = ()

    def __new__(cls, value):
        assert not isinstance(value, BinaryAddr)
        return int.__new__(cls, value)

    def __add__(self, other):
        return RuntimeAddr(int.__add__(self, other))

# Address validation
def is_valid_runtime_addr(runtime_addr, allow_final_address = False):
    """Validate a runtime address."""

    assert not isinstance(runtime_addr, BinaryAddr)
    if allow_final_address:
        return 0 <= runtime_addr <= 0x10000
    return 0 <= runtime_addr < 0x10000

def is_valid_binary_addr(binary_addr, allow_final_address = False):
    """Validate a binary address."""

    assert not isinstance(binary_addr, RuntimeAddr)
    if allow_final_address:
        return 0 <= binary_addr <= 0x10000
    return 0 <= binary_addr < 0x10000


# Memory access by binary address
def get_u8_binary(binary_addr):
    """Get 8 bit number given a binary address"""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None, "Bad address {0}".format(hex(binary_addr))
    return memory_binary[binary_addr]

def get_u16_binary(binary_addr):
    """Get 16 bit number (little-endian) given a binary address"""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None, "Nothing loaded at address {0}".format(hex(binary_addr))
    assert memory_binary[binary_addr+1] is not None, "Nothing loaded at address {0} (supposed 2nd byte of 16 bit address)".format(hex(binary_addr+1))
    return memory_binary[binary_addr] + (memory_binary[binary_addr+1] << 8)

def get_u16_be_binary(binary_addr):
    """Get 16 bit number (big-endian) given a binary address"""

    memory_binary = session.current().memory.binary
    assert memory_binary[binary_addr] is not None and memory_binary[binary_addr+1] is not None
    return (memory_binary[binary_addr] << 8) | memory_binary[binary_addr+1]



# Memory access by runtime address
def get_u8_runtime(runtime_addr):
    """Get 8 bit number given a runtime address"""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u8_binary(binary_loc.binary_addr)

def get_u16_runtime(runtime_addr):
    """Get 16 bit number (little-endian) given a runtime address"""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u16_binary(binary_loc.binary_addr)

def get_u16_be_runtime(runtime_addr):
    """Get 16 bit number (big-endian) given a runtime address"""

    import movemanager
    binary_loc = movemanager.r2b_checked(runtime_addr)
    return get_u16_be_binary(binary_loc.binary_addr)

class BinaryLocation:
    """BinaryLocation holds a binary address and move id"""

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
        """Overrides the default implementation"""
        if isinstance(other, BinaryLocation):
            return (self.binary_addr == other.binary_addr) and (self.move_id == other.move_id)
        return NotImplemented

    def __hash__(self):
        """Overrides the default implementation"""
        return hash((self.binary_addr, self.move_id))

class MemoryRuntime:
    """Class for reading runtime memory with address validation"""

    def __getitem__(self, runtime_addr):
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
    address, for control files (see 'memory_binary' below)."""

    def __getitem__(self, binary_addr):
        return session.current().memory.binary[binary_addr]

    def __setitem__(self, binary_addr, value):
        session.current().memory.binary[binary_addr] = value

    def __len__(self):
        return len(session.current().memory.binary)

    def __iter__(self):
        return iter(session.current().memory.binary)

class Memory:
    """The memory of one session (see session.py)."""

    def __init__(self):
        # We store 64K of memory. Some portion of this will hold the binary
        # file(s) to disassemble. Use the get_u*() functions above to access
        # this memory since this includes proper address validation.
        self.binary = [None] * 64*1024

        # Stores a (start_binary_addr, end_binary_addr) pair for each load()
        self.load_ranges = []

        # The files loaded, in the order loaded: a LoadedFile for each load()
        self.loaded_files = []

class LoadedFile:
    """A file loaded with load() or load_prg(): its filename (as given), and
    the binary addresses it's loaded at, from 'start' up to (but not
    including) 'end'. 'offset' is where in the file the data loaded starts,
    and 'prg' is True for a PRG file loaded with load_prg()."""

    def __init__(self, filename, start, end, offset=0, prg=False):
        self.filename = filename
        self.start = start
        self.end = end
        self.offset = offset
        self.prg = prg

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
# validation. (This perhaps should more properly be called memory_runtime, but
# earlier versions just had 'memory' and this is the main memory access for
# user code so probably reasonable to use a short name for it.)
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
    """Get the whole binary address range for any loaded data"""

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

def load(filename, binary_addr, md5sum=None, offset=0, length=None, *, prg=False, command=None):
    """Load a binary file (or the part of it from 'offset', for 'length'
    bytes or to the end) into memory at the given address.

    Checks the md5 checksum (of the whole file) matches if given. 'command'
    describes the command for messages, e.g. "load(&2000, 'file')"."""

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

    # Loading over data loaded earlier replaces it, as it always has, but is
    # probably a mistake
    end_addr = binary_addr + len(data)
    for earlier in memory.loaded_files:
        if earlier.start < end_addr and binary_addr < earlier.end:
            utils.warn("{0}: this replaces some of the data loaded from {1}".format(command, earlier.describe()))

    memory.binary[binary_addr:end_addr] = data
    memory.load_ranges.append((binary_addr, end_addr))
    memory.loaded_files.append(LoadedFile(filename, int(binary_addr), int(end_addr), offset, prg))

def prg_header_addr():
    """If the output starts with a PRG file's two-byte load address (see
    load_prg()), so that it assembles to the whole PRG file, the load address;
    otherwise None. That's when a PRG file is loaded at the lowest address
    loaded (and at &0002 or above)."""
    memory = session.current().memory
    if not memory.load_ranges:
        return None
    start, _ = get_entire_load_range()
    for loaded_file in memory.loaded_files:
        if loaded_file.prg and loaded_file.start == start and start >= 2:
            return int(start)
    return None

def is_data_loaded_at_binary_addr(binary_addr, n=1):
    assert all(is_valid_binary_addr(x) for x in range(binary_addr, binary_addr+n))
    memory_binary = session.current().memory.binary
    return all(memory_binary[binary_addr + i] is not None for i in range(n))

