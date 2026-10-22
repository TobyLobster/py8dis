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

def load(filename, binary_addr, md5sum=None):
    """Load a binary file into memory at the given address.

    Checks the md5 checksum matches if given."""

    binary_addr = BinaryAddr(binary_addr)
    memory = session.current().memory

    try:
        with open(filename, "rb") as f:
            data = bytearray(f.read())
            if binary_addr + len(data) > 0x10000:
                utils.die("load() would overflow memory")
            memory.binary[binary_addr:binary_addr+len(data)] = data
    except FileNotFoundError:
        utils.die("File '{0}' not found".format(filename))

    if md5sum is not None:
        import hashlib
        hash = hashlib.md5()
        hash.update(data)
        if md5sum != hash.hexdigest():
            utils.die("load() md5sum doesn't match")
    memory.load_ranges.append((binary_addr, binary_addr + len(data)))

def is_data_loaded_at_binary_addr(binary_addr, n=1):
    assert all(is_valid_binary_addr(x) for x in range(binary_addr, binary_addr+n))
    memory_binary = session.current().memory.binary
    return all(memory_binary[binary_addr + i] is not None for i in range(n))

