"""
CP/M specific functions: cpm.cpm() names and comments a CP/M program's use of
page zero and the BDOS, for the Z80 or the 8080, as acorn.bbc() and
commodore.c64() do for those machines.

    import cpm
    load(0x0100, "program.com", "z80")
    cpm.cpm()

A call to the BDOS (CALL 5, or JP 5) with the function number in C known is
commented with what it does (e.g. 'Print the string at DE, up to a "$"'),
and the 'ld c,n' that sets C is given the function's name (e.g. 'ld
c,C_WRITESTR'). A program that calls the BDOS through a routine of its own
can say so with bdos_wrapper().

The functions' names are those of Digital Research's CP/M 3 documentation
(see https://www.seasip.info/Cpm/bdos.html), in capitals unless
config.set_upper_case_os_calls(False) is used first, as is the name of the
BDOS's entry point (BDOS).
"""

from commands import *
import classification
import config
import cpu8080
import cpuz80
import disassembly
import memorymanager
import movemanager
import session
import utils
from align import Align
from binaryaddrtype import BinaryAddrType
from memorymanager import BinaryAddr, RuntimeAddr

BDOS_ENTRY = 0x0005     # CALL 5 calls the BDOS (and the address at 6 is the top of the memory for programs)

# What the BDOS function takes in DE (for bdos_functions below)
CHARACTER = "character"         # E is a character (e.g. to write)
STRING = "string"               # DE is the address of a string ending with '$'
BUFFER = "buffer"               # DE is the address of a buffer for a line of input
FCB = "fcb"                     # DE is the address of a file control block
DMA = "dma"                     # DE is the address of the buffer for reading and writing records

# The BDOS functions of CP/M 2.2 and CP/M 3, by number: the name, a
# description, and what DE (or E) is, if it's used (see above)
bdos_functions = {
      0: ("P_TERMCPM",    "End the program (warm boot)", None),
      1: ("C_READ",       "Read a character from the console (into A)", None),
      2: ("C_WRITE",      "Write the character in E to the console", CHARACTER),
      3: ("A_READ",       "Read a character from the reader (into A)", None),
      4: ("A_WRITE",      "Write the character in E to the punch", CHARACTER),
      5: ("L_WRITE",      "Write the character in E to the printer", CHARACTER),
      6: ("C_RAWIO",      "Direct console input or output (E)", None),
      7: ("A_STATIN",     "Get the IOBYTE (CP/M 3: the auxiliary input status)", None),
      8: ("A_STATOUT",    "Set the IOBYTE to E (CP/M 3: get the auxiliary output status)", None),
      9: ("C_WRITESTR",   "Print the string at DE, up to a '$'", STRING),
     10: ("C_READSTR",    "Read a line from the console into the buffer at DE", BUFFER),
     11: ("C_STAT",       "Get the console status (A is not 0 if a key is waiting)", None),
     12: ("S_BDOSVER",    "Get the version number (into HL)", None),
     13: ("DRV_ALLRESET", "Reset the disc system", None),
     14: ("DRV_SET",      "Select drive E (0 is A:)", None),
     15: ("F_OPEN",       "Open the file whose FCB is at DE", FCB),
     16: ("F_CLOSE",      "Close the file whose FCB is at DE", FCB),
     17: ("F_SFIRST",     "Search for the first file matching the FCB at DE", FCB),
     18: ("F_SNEXT",      "Search for the next matching file", None),
     19: ("F_DELETE",     "Delete the files matching the FCB at DE", FCB),
     20: ("F_READ",       "Read the next record of the file whose FCB is at DE", FCB),
     21: ("F_WRITE",      "Write the next record of the file whose FCB is at DE", FCB),
     22: ("F_MAKE",       "Create the file whose FCB is at DE", FCB),
     23: ("F_RENAME",     "Rename the file whose FCB is at DE", FCB),
     24: ("DRV_LOGINVEC", "Get the drives logged in (a bit for each, into HL)", None),
     25: ("DRV_GET",      "Get the current drive (into A, 0 is A:)", None),
     26: ("F_DMAOFF",     "Set the DMA address (for reading and writing records) to DE", DMA),
     27: ("DRV_ALLOCVEC", "Get the address of the allocation vector (into HL)", None),
     28: ("DRV_SETRO",    "Make the current drive read-only", None),
     29: ("DRV_ROVEC",    "Get the read-only drives (a bit for each, into HL)", None),
     30: ("F_ATTRIB",     "Set the attributes of the file whose FCB is at DE", FCB),
     31: ("DRV_DPB",      "Get the address of the disc parameter block (into HL)", None),
     32: ("F_USERNUM",    "Set the user number to E (or get it, if E is $FF)", None),
     33: ("F_READRAND",   "Read a random record of the file whose FCB is at DE", FCB),
     34: ("F_WRITERAND",  "Write a random record of the file whose FCB is at DE", FCB),
     35: ("F_SIZE",       "Get the size of the file whose FCB is at DE", FCB),
     36: ("F_RANDREC",    "Set the random record of the FCB at DE", FCB),
     37: ("DRV_RESET",    "Reset the drives in DE (a bit for each)", None),
     40: ("F_WRITEZF",    "Write a random record, with zero fill, of the file whose FCB is at DE", FCB),
     44: ("F_MULTISEC",   "Set the number of records to read or write at once to E", None),
     45: ("F_ERRMODE",    "Set the BDOS error mode (E)", None),
     46: ("DRV_SPACE",    "Get the free space on drive E", None),
     47: ("P_CHAIN",      "Run the command at the DMA address", None),
     48: ("DRV_FLUSH",    "Write any pending data to the discs", None),
     49: ("S_SCB",        "Get or set the system control block (the parameters at DE)", None),
     50: ("S_BIOS",       "Call the BIOS (the parameters at DE)", None),
     98: ("F_CLEANUP",    "Free the blocks of files not closed", None),
     99: ("F_TRUNCATE",   "Truncate the file whose FCB is at DE", FCB),
    100: ("DRV_SETLABEL", "Set the directory label (the FCB at DE)", FCB),
    101: ("DRV_GETLABEL", "Get the directory label byte of drive E", None),
    102: ("F_TIMEDATE",   "Get the time stamps of the file whose FCB is at DE", FCB),
    103: ("F_WRITEXFCB",  "Set the password of the file whose FCB is at DE", FCB),
    104: ("T_SET",        "Set the date and time (from DE)", None),
    105: ("T_GET",        "Get the date and time (into DE)", None),
    106: ("F_PASSWD",     "Set the default password (at DE)", None),
    107: ("S_SERIAL",     "Get the serial number (into DE)", None),
    108: ("P_CODE",       "Get or set the program's return code (DE)", None),
    109: ("C_MODE",       "Get or set the console mode (DE)", None),
    110: ("C_DELIMIT",    "Get or set the string delimiter (E)", None),
    111: ("C_WRITEBLK",   "Write a block of characters to the console (the parameters at DE)", None),
    112: ("L_WRITEBLK",   "Write a block of characters to the printer (the parameters at DE)", None),
}

# C_RAWIO (function 6)'s E, other than a character to write
_RAWIO = {
    0xff: "Read a character from the console without echoing it (0 if none)",
    0xfe: "Get the console status (A is not 0 if a key is waiting)",
    0xfd: "Read a character from the console without echoing it (waiting for one)",
}

# F_ERRMODE (function 45)'s E
_ERRMODE = {
    0xff: "Set the BDOS error mode to return errors",
    0xfe: "Set the BDOS error mode to return and display errors",
}

# The control characters with names (for the characters written)
_CONTROL_CHARACTERS = {
    0x07: "bell",
    0x08: "backspace",
    0x09: "tab",
    0x0a: "line feed",
    0x0c: "form feed",
    0x0d: "carriage return",
    0x1a: "clear screen",
    0x1b: "escape",
}

def character_description(c):
    """A description of a character written to the console, e.g. "'A'" or
    "$0D (carriage return)"."""
    if utils.isprint(c):
        return "'%s'" % chr(c)
    if c in _CONTROL_CHARACTERS:
        return "$%02X (%s)" % (c, _CONTROL_CHARACTERS[c])
    return "$%02X" % c

def bdos_name():
    """The name of the BDOS's entry point: BDOS (or bdos, with
    config.set_upper_case_os_calls(False))."""
    return _os_name("BDOS")

def function_name(number):
    """The name of a BDOS function (see bdos_functions), e.g. C_WRITESTR (or
    c_writestr, with config.set_upper_case_os_calls(False)), or None if
    it's not one of them."""
    if number not in bdos_functions:
        return None
    return _os_name(bdos_functions[number][0])

def _os_name(name):
    return name.upper() if config.get_upper_case_os_calls() else name.lower()

def page_zero_names():
    """The names of the addresses in page zero, as a list of (address, name,
    the address of the name it's based on, or None), e.g. (0x0006,
    'BDOS+1', 0x0005)."""
    bdos = bdos_name()
    result = [
        (0x0000, "warm_boot", None),            # (JP to the BIOS's warm boot)
        (0x0001, "warm_boot+1", 0x0000),        # (the address of the BIOS's warm boot entry)
        (0x0002, "warm_boot+2", 0x0000),
        (0x0003, "iobyte", None),
        (0x0004, "current_drive", None),        # (the current drive, and the user number in the top 4 bits)
        (BDOS_ENTRY, bdos, None),               # (JP to the BDOS)
        (0x0006, bdos + "+1", BDOS_ENTRY),      # (the address of the BDOS: the top of the memory for programs)
        (0x0007, bdos + "+2", BDOS_ENTRY),
        (0x005c, "default_fcb", None),          # (the first file name in the command, as an FCB)
        (0x006c, "second_fcb", None),           # (the second file name in the command)
        (0x0080, "default_dma", None),          # (the command's tail: its length, then the text, and the default DMA buffer)
    ]
    for i in range(1, 16):
        result.append((0x005c + i, "default_fcb+%d" % i, 0x005c))
        result.append((0x006c + i, "second_fcb+%d" % i, 0x006c))
    for i in range(32, 36):
        result.append((0x005c + i, "default_fcb+%d" % i, 0x005c))
    for i in range(1, 128):
        result.append((0x0080 + i, "default_dma+%d" % i, 0x0080))
    return sorted(result)


def _set_up_done():
    return session.current().extras.get("cpm.wrappers") is not None

def cpm():
    """Name and comment a CP/M program's use of page zero and the BDOS (call
    it after load(), with the "z80" or "8080" CPU):

    - names for page zero's addresses (e.g. 'iobyte', 'default_fcb' and
      'default_dma'), the BDOS's entry point (BDOS) and the address after
      it (BDOS+1, which holds the top of the memory for programs), output
      only if used;
    - each call or jump to the BDOS (CALL 5) with the function number in C
      known commented with what the function does (e.g. 'Print the string
      at DE, up to a "$"', or "Write 'A' to the console" when E is known
      too), and the 'ld c,n' that sets C given the function's name (e.g.
      'ld c,C_WRITESTR'), defined as a constant;
    - for a function that takes an address in DE, the 'ld de,nn' that sets
      it written with the address's label (e.g. 'ld de,default_fcb'); a
      string to print ('$' terminated) is classified and named 'message' if
      it hasn't been already, and a file control block 'fcb', a buffer for
      a line of input 'input_buffer' and a DMA buffer 'dma_buffer', if they
      have no name.

    See bdos_wrapper() for a routine of the program's own that calls the
    BDOS.
    """
    cpu = session.current().cpu
    if not isinstance(cpu, (cpuz80.CpuZ80, cpu8080.Cpu8080)):
        utils.die("cpm.cpm(): call load(..., \"z80\") or load(..., \"8080\") first")
    if _set_up_done():
        utils.die("cpm.cpm(): this has already been called")
    extras = session.current().extras
    extras["cpm.wrappers"] = {RuntimeAddr(BDOS_ENTRY): "c"}
    # (So that config.set_upper_case_os_calls() can't be called now)
    extras["os_calls_named"] = True

    for addr, name, base in page_zero_names():
        optional_label(addr, name, base)

    session.current().trace.analysis_hooks.append(_analysis)

def bdos_wrapper(runtime_addr, register="c"):
    """Say that the routine at runtime_addr calls the BDOS (see cpm()), with
    the function number in the register (C, as the BDOS has it, or A), so
    that calls to it are commented as calls to the BDOS are."""
    if not _set_up_done():
        utils.die("cpm.bdos_wrapper(): call cpm.cpm() first")
    if register not in ("a", "c"):
        utils.die("cpm.bdos_wrapper({0}, {1!r}): the register must be \"a\" or \"c\"".format(config.get_assembler().hex(runtime_addr), register))
    session.current().extras["cpm.wrappers"][RuntimeAddr(runtime_addr)] = register


# ************************************************************************************************
# The analysis, once the code is traced: the same bytes for the Z80 and the
# 8080

# The opcodes that call or jump to a 16 bit address (unconditionally or not)
_CALLS_AND_JUMPS = {0xcd, 0xc3,
                    0xc4, 0xcc, 0xd4, 0xdc, 0xe4, 0xec, 0xf4, 0xfc,
                    0xc2, 0xca, 0xd2, 0xda, 0xe2, 0xea, 0xf2, 0xfa}

# The opcodes that load a register with an 8 bit value ('ld r,n')
_LD_R_N = {0x3e: "a", 0x0e: "c", 0x1e: "e"}
_LD_DE_NN = 0x11

def _analysis():
    """Comment each call to the BDOS (or a wrapper), name the function
    number and the address in DE (see cpm())."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    labels = session.current().labels.labels
    wrappers = session.current().extras["cpm.wrappers"]
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = range_start
        state = cpu.CpuState()
        loads = {}          # (the binary address of the last 'ld r,n' or 'ld de,nn' for each register, since what's known started)
        while binary_addr < range_end:
            c = classification.get_classification(binary_addr)
            if c is None or not c.is_code(binary_addr):
                state = cpu.CpuState()
                loads = {}
                binary_addr += 1 if c is None else c.length()
                continue
            runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))
            if runtime_addr in labels:
                # (Code can come here from elsewhere)
                state = cpu.CpuState()
                loads = {}
            opcode = memory_binary[binary_addr]
            if opcode in _CALLS_AND_JUMPS and c.length() == 3:
                register = wrappers.get(RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1)))
                if register is not None:
                    _bdos_call(binary_addr, runtime_addr, register, state, loads)
            elif opcode in _LD_R_N and c.length() == 2:
                loads[_LD_R_N[opcode]] = binary_addr
            elif opcode == _LD_DE_NN and c.length() == 3:
                loads["de"] = binary_addr
            if c.is_block_end():
                state = cpu.CpuState()
                loads = {}
            else:
                state = cpu.cpu_states[binary_addr] or cpu.CpuState()
            binary_addr += c.length()

def _load_operand(loads, register, value):
    """The binary address of the operand of the last 'ld r,n' (or 'ld
    de,nn') that loaded the register with the value, or None."""
    binary_addr = loads.get(register)
    if binary_addr is None:
        return None
    if register == "de":
        if memorymanager.get_u16_binary(binary_addr + 1) != value:
            return None
    elif session.current().memory.binary[binary_addr + 1] != value:
        return None
    return BinaryAddr(binary_addr + 1)

def _bdos_call(binary_addr, runtime_addr, register, state, loads):
    """A call (or jump) to the BDOS (or a wrapper) with the function number
    in the register: comment it, and name the function number and DE."""
    number = state[register]
    if number is None or number not in bdos_functions:
        return
    name, description, de_use = bdos_functions[number]

    # The function number's name
    operand = _load_operand(loads, register, number)
    if operand is not None:
        name = function_name(number)
        expressions = session.current().classifications.expressions
        if operand not in expressions and classification.add_expression(operand, name, force=False, auto_generated=True) is not None:
            constants = session.current().extras.setdefault("cpm.constants", set())
            if number not in constants:
                constants.add(number)
                constant(number, name)

    # What it does, with E if it's known
    e = state["e"]
    if e is not None:
        if de_use == CHARACTER:
            description = description.replace("the character in E", character_description(e))
        elif number == 6:
            description = _RAWIO.get(e, "Write %s to the console (directly)" % character_description(e))
        elif number == 45:
            description = _ERRMODE.get(e, "Set the BDOS error mode to the default (stop the program on errors)")
        elif number == 14 and e < 16:
            description = "Select drive %s:" % chr(ord("A") + e)
        elif number == 32 and e == 0xff:
            description = "Get the user number (into A)"
    disassembly.comment(runtime_addr, description, align=Align.INLINE, word_wrap=False, auto_generated=True)

    # The address in DE
    if de_use not in (STRING, BUFFER, FCB, DMA) or state["d"] is None or e is None:
        return
    de = state["d"] << 8 | e
    operand = _load_operand(loads, "de", de)
    if operand is None:
        return
    target = RuntimeAddr(de)
    target_binary_addr, _ = movemanager.r2b(target)
    if target_binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(target_binary_addr):
        name = {STRING: "message", BUFFER: "input_buffer", FCB: "fcb", DMA: "dma_buffer"}[de_use]
        if de_use == STRING:
            if not classification.is_classified(target_binary_addr):
                _name_data(target, name)
                stringterm(target, ord("$"))
        else:
            _name_data(target, name)
    label = disassembly.get_label(target, operand, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
    classification.add_expression(operand, label, force=False, auto_generated=True)

def _name_data(runtime_addr, name):
    """Label the address, if it has no name yet, with the name (or name_2
    etc. if that's taken)"""
    labels = session.current().labels.labels
    if runtime_addr in labels and labels[runtime_addr].explicit_names:
        return
    counts = session.current().extras.setdefault("cpm.data_names", {})
    count = counts.get(name, 0) + 1
    counts[name] = count
    label(runtime_addr, name if count == 1 else "%s_%d" % (name, count))
