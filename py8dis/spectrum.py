"""
ZX Spectrum specific functions: spectrum.spectrum48() names and comments a Z80
program's use of the 48K Spectrum's ROM, system variables and hardware, as
acorn.bbc() and commodore.c64() do for those machines; rom() does the rest
for a disassembly of the ROM itself.

    import spectrum
    load(0x8000, "game.bin", "z80")
    spectrum.spectrum48()

See spectrumtables.py for the names.
"""

from commands import *
import classification
import cpuz80
import cpuz80state
import memorymanager
import movemanager
import session
import utils
from binaryaddrtype import BinaryAddrType
from format import Format
from memorymanager import BinaryAddr, RuntimeAddr

from spectrumtables import *


def _set_up_done():
    return session.current().extras.get("spectrum.machine") is not None


# ************************************************************************************************
# The names

def location_names(rom_labels=True):
    """The names spectrum48() gives memory locations, as a list of
    (address, name, base address or None): one for each byte of each system
    variable (e.g. 'frames+1', with the base address of 'frames'), the
    screen, the attributes and the printer buffer, and (with rom_labels) the
    ROM's routines and tables."""
    result = []
    for location in system_variables + screen_locations:
        result.append((location.addr, location.name, None))
        for i in range(1, location.size):
            result.append((location.addr + i, "%s+%d" % (location.name, i), location.addr))
    if rom_labels:
        for addr in sorted(rom_names):
            result.append((addr, rom_names[addr], None))
    return result

def _location_name(addr):
    """The (base) address of the location named for addr: the system
    variable, or the screen etc., or None."""
    for location in system_variables + screen_locations:
        if location.addr <= addr < location.addr + location.size:
            return location.addr
    return None


# ************************************************************************************************
# The ROM's calls followed by data: RST $08 (an error number) and RST $28
# (the calculator's bytecode)

def error_report_text(n):
    """Error report n's code and text, e.g. '6 Number too big'"""
    return "%s %s" % ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[n], error_reports[n])

def error_hook(target, caller):
    """RST $08 (ERROR-1) is followed by the error number, one less than the
    report's code (so $FF is report 0, OK). It doesn't return."""
    addr = caller + 1
    if not _loaded_and_unclassified(addr, 1):
        return None
    n = (get_u8_runtime(addr) + 1) & 0xff
    byte(addr)
    if n < len(error_reports):
        comment(addr, "Report " + error_report_text(n), inline=True)
    return None

CALCULATOR_OPS = {
    0x00: "jump-true", 0x01: "exchange", 0x02: "delete", 0x03: "subtract",
    0x04: "multiply", 0x05: "division", 0x06: "to-power", 0x07: "or",
    0x08: "no-&-no", 0x09: "no-l-eql", 0x0a: "no-gr-eq", 0x0b: "nos-neql",
    0x0c: "no-grtr", 0x0d: "no-less", 0x0e: "nos-eql", 0x0f: "addition",
    0x10: "str-&-no", 0x11: "str-l-eql", 0x12: "str-gr-eq", 0x13: "strs-neql",
    0x14: "str-grtr", 0x15: "str-less", 0x16: "strs-eql", 0x17: "strs-add",
    0x18: "val$", 0x19: "usr-$", 0x1a: "read-in", 0x1b: "negate",
    0x1c: "code", 0x1d: "val", 0x1e: "len", 0x1f: "sin",
    0x20: "cos", 0x21: "tan", 0x22: "asn", 0x23: "acs",
    0x24: "atn", 0x25: "ln", 0x26: "exp", 0x27: "int",
    0x28: "sqr", 0x29: "sgn", 0x2a: "abs", 0x2b: "peek",
    0x2c: "in", 0x2d: "usr-no", 0x2e: "str$", 0x2f: "chr$",
    0x30: "not", 0x31: "duplicate", 0x32: "n-mod-m", 0x33: "jump",
    0x34: "stk-data", 0x35: "dec-jr-nz", 0x36: "less-0", 0x37: "greater-0",
    0x38: "end-calc", 0x39: "get-argt", 0x3a: "truncate", 0x3b: "fp-calc-2",
    0x3c: "e-to-fp", 0x3d: "re-stack",
}
CALCULATOR_CONSTANTS = ("stk-zero", "stk-one", "stk-half", "stk-pi/2", "stk-ten")

def calculator_op_name(op):
    """The name of the calculator's bytecode instruction op, or None if it
    isn't one."""
    if op in CALCULATOR_OPS:
        return CALCULATOR_OPS[op]
    if 0x80 <= op < 0xa0:
        return "series-%02X" % (op & 0x1f)
    if 0xa0 <= op < 0xa0 + len(CALCULATOR_CONSTANTS):
        return CALCULATOR_CONSTANTS[op - 0xa0]
    if 0xc0 <= op < 0xc6:
        return "st-mem-%d" % (op - 0xc0)
    if 0xe0 <= op < 0xe6:
        return "get-mem-%d" % (op - 0xe0)
    return None

def calculator_number_value(addr):
    """The number in the calculator's compressed format at addr (as
    STK-DATA reads it), and its length in bytes. The first byte's top two
    bits are the number of mantissa bytes, less 1, and the rest the
    exponent, less $50, or 0 if that's in the next byte. Missing mantissa
    bytes are 0. An exponent of 0 (e.g. $B0 + $50) is a small integer: its
    first mantissa byte is the sign (0 or $FF), then its low and high
    bytes."""
    first = get_u8_runtime(addr)
    count = (first >> 6) + 1
    exponent = first & 0x3f
    length = 1 + count
    if exponent == 0:
        exponent = get_u8_runtime(addr + 1)
        length += 1
    exponent = (exponent + 0x50) & 0xff
    mantissa = [get_u8_runtime(addr + length - count + i) for i in range(count)] + [0] * (4 - count)
    if exponent == 0:
        value = mantissa[1] | (mantissa[2] << 8)
        if mantissa[0]:
            value -= 0x10000
    else:
        # (The mantissa's top bit is the sign; it's always 1 in the value)
        sign = -1 if mantissa[0] & 0x80 else 1
        value = (mantissa[0] | 0x80) / 0x100
        for i, m in enumerate(mantissa[1:]):
            value += m / 0x100 ** (i + 2)
        value = sign * value * 2.0 ** (exponent - 0x80)
    return value, length

def calculator_number(addr):
    """Classify the number in the calculator's compressed format at addr
    (see calculator_number_value()), with its value in a comment, returning
    the address after it."""
    value, length = calculator_number_value(addr)
    byte(addr, length)
    comment(addr, "%.10g" % value, inline=True)
    return addr + length

def _loaded_and_unclassified(runtime_addr, length):
    """Whether the bytes are loaded and not yet classified."""
    binary_loc = movemanager.r2b(RuntimeAddr(runtime_addr))
    binary_addr = binary_loc[0]
    return binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr, length) and \
           not classification.is_classified(binary_addr, length)

def calculator(addr):
    """Classify the calculator's bytecode at addr (up to an end-calc,
    following its jumps), with each instruction's name in a comment.
    Returns the address after the end-calc it reaches first, where the Z80
    code continues, or None if it doesn't reach one (or reaches bytecode
    classified already, whose end-calcs have been dealt with). Code after
    any other end-calc it reaches is traced too."""
    addr = int(addr)
    todo = [addr]
    resume = []
    while todo:
        addr = todo.pop(0)
        while _loaded_and_unclassified(addr, 1):
            op = get_u8_runtime(addr)
            name = calculator_op_name(op)
            if name is None:
                # (Not bytecode after all: stop here)
                break
            byte(addr)
            comment(addr, name, inline=True)
            addr += 1
            if op == 0x38:                          # end-calc
                resume.append(addr)
                break
            if op in (0x00, 0x33, 0x35):            # jump-true, jump, dec-jr-nz
                if not _loaded_and_unclassified(addr, 1):
                    break
                offset = get_u8_runtime(addr)
                target = addr + (offset - 0x100 if offset >= 0x80 else offset)
                byte(addr)
                expr(addr, get_label(target, addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE) + " - $")
                todo.append(target)
                addr += 1
                if op == 0x33:                      # (jump always jumps)
                    break
            elif op == 0x34:                        # stk-data, then a number
                addr = calculator_number(addr)
            elif 0x80 <= op < 0xa0:                 # series-xx, then the numbers
                for _ in range(op & 0x1f):
                    addr = calculator_number(addr)
    if not resume:
        return None
    for addr in resume[1:]:
        entry(addr)
    return resume[0]

def calculator_hook(target, caller):
    """RST $28 (FP-CALC), or a CALL to GEN-ENT-1 or GEN-ENT-2: the
    calculator's bytecode follows."""
    return calculator(int(caller) + (1 if target == 0x0028 else 3))

# The calls followed by data, by address
_DATA_CALLS = {0x0008: error_hook, 0x0028: calculator_hook, 0x335e: calculator_hook, 0x3362: calculator_hook}


# ************************************************************************************************
# Comments on the code

CONTROL_CODES = {
    0x06: "comma", 0x08: "cursor left", 0x0d: "ENTER", 0x10: "INK", 0x11: "PAPER",
    0x12: "FLASH", 0x13: "BRIGHT", 0x14: "INVERSE", 0x15: "OVER", 0x16: "AT", 0x17: "TAB",
}

def character_description(c):
    """A description of a character printed with RST $10, e.g. "'A'" or
    '$16 (AT)'."""
    if 0x20 <= c < 0x7f and c != 0x60:
        return "'%s'" % chr(c)
    if c == 0x60:
        return "$60 (pound sign)"
    if c == 0x7f:
        return "$7F (copyright sign)"
    if c in CONTROL_CODES:
        return "$%02X (%s)" % (c, CONTROL_CODES[c])
    if 0x80 <= c < 0x90:
        return "$%02X (block graphic)" % c
    if 0x90 <= c < 0xa5:
        return "$%02X (user-defined graphic %s)" % (c, chr(ord("A") + c - 0x90))
    if c >= 0xa5:
        return "$%02X (keyword %s)" % (c, keywords[c - 0xa5])
    return "$%02X" % c

# The control codes followed by parameters, and what those are
CONTROL_PARAMETERS = {
    0x10: ("INK's colour",), 0x11: ("PAPER's colour",), 0x12: ("FLASH's 0 or 1",), 0x13: ("BRIGHT's 0 or 1",),
    0x14: ("INVERSE's 0 or 1",), 0x15: ("OVER's 0 or 1",), 0x16: ("AT's line", "AT's column"), 0x17: ("TAB's column", "(TAB's high byte)"),
}

def print_hook(runtime_addr, state, subroutine):
    """RST $10 (PRINT-A): what's printed, if A is known. (After a control
    code that takes parameters, e.g. AT, the next calls within a few bytes
    are taken to be printing them.)"""
    if subroutine.runtime_addr == runtime_addr:
        return
    extras = session.current().extras
    previous_addr, pending = extras.get("spectrum.print_parameters", (None, ()))
    if previous_addr is None or not 0 < runtime_addr - previous_addr <= 16:
        pending = ()
    a = state["a"]
    if pending:
        description = "%d (%s)" % (a, pending[0]) if a is not None else pending[0]
        pending = pending[1:]
    elif a is not None:
        description = character_description(a)
        pending = CONTROL_PARAMETERS.get(a, ())
    else:
        description = None
    extras["spectrum.print_parameters"] = (runtime_addr, pending)
    comment(runtime_addr, subroutine.title if description is None else "Print " + description, inline=True)

def border_description(value):
    """What writing value to the ULA's port does."""
    text = "Border " + colours[value & 7]
    if value & 0x08:
        text += ", MIC on"
    if value & 0x10:
        text += ", speaker on"
    return text

def keyboard_description(high_byte):
    """Which keyboard half rows reading the ULA's port with high_byte reads."""
    rows = [keyboard_half_rows[i] for i in range(8) if not high_byte & (1 << i)]
    if not rows:
        return None
    return "Read the keyboard (%s)" % ", ".join(rows)

def _previous_state(cpu, binary_addr, previous_binary_addr):
    """The CPU state before the instruction at binary_addr (after the one at
    previous_binary_addr, if it's code that runs on into this one, and code
    can't come to this one from elsewhere, at a label)."""
    runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))
    if previous_binary_addr is None or runtime_addr in session.current().labels.labels:
        return cpu.CpuState()
    return cpu.cpu_states[previous_binary_addr] or cpu.CpuState()

def _analysis():
    """Write each (IY+d) as a system variable (unless IY is known not to be
    ERR_NR's address), name the ULA's port, and comment what's written to it
    and read from it."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    expressions = session.current().classifications.expressions
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = range_start
        previous = None
        while binary_addr < range_end:
            c = classification.get_classification(binary_addr)
            if not isinstance(c, cpu.Opcode):
                previous = None
                binary_addr += 1 if c is None else c.length()
                continue
            state = _previous_state(cpu, binary_addr, previous)
            runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))

            # (IY+d): IY holds ERR_NR's address
            index = c.part(cpuz80.Index)
            if index is not None and index.register == "iy":
                iyh, iyl = state["iyh"], state["iyl"]
                d_addr = binary_addr + index.offset
                if (iyh is None or iyl is None or (iyh << 8 | iyl) == IY_BASE) and d_addr not in expressions:
                    d = memory_binary[d_addr]
                    target = IY_BASE + (d - 0x100 if d >= 0x80 else d)
                    if _location_name(target) is not None:
                        d_runtime_addr = movemanager.b2r(BinaryAddr(d_addr))
                        expr(d_runtime_addr, make_subtract(get_label(target, d_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE),
                                                           get_label(IY_BASE, d_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)))

            # The ULA's port
            port = c.part(cpuz80.Port)
            if port is not None and memory_binary[binary_addr + port.offset] == ULA_PORT:
                port_addr = binary_addr + port.offset
                if port_addr not in expressions:
                    expr(movemanager.b2r(BinaryAddr(port_addr)), "ula_port")
                    session.current().extras["spectrum.ula_port_used"] = True
                a = state["a"]
                if a is not None:
                    # (out (n),a writes A to the port; in a,(n) puts A on
                    # the address bus's high byte)
                    text = border_description(a) if c.mnemonic == "out" else keyboard_description(a)
                    if text is not None:
                        comment(runtime_addr, text, inline=True)
            elif c.key in ((0xed, 0x41), (0xed, 0x49), (0xed, 0x51), (0xed, 0x59), (0xed, 0x61), (0xed, 0x69), (0xed, 0x79),
                           (0xed, 0x40), (0xed, 0x48), (0xed, 0x50), (0xed, 0x58), (0xed, 0x60), (0xed, 0x68), (0xed, 0x78)):
                # out (c),r or in r,(c), with C even (the ULA)
                b, port_low = state["b"], state["c"]
                reg = cpuz80state.R[(c.key[1] >> 3) & 7]
                if port_low is not None and port_low & 1 == 0:
                    if c.key[1] & 1:
                        value = state[reg]
                        if value is not None:
                            comment(runtime_addr, border_description(value), inline=True)
                    elif b is not None:
                        text = keyboard_description(b)
                        if text is not None:
                            comment(runtime_addr, text, inline=True)

            previous = binary_addr if not c.is_block_end() else None
            binary_addr += c.length()

    if session.current().extras.get("spectrum.ula_port_used"):
        constant(ULA_PORT, "ula_port", format=Format.HEX)


# ************************************************************************************************
# The set up

def spectrum48(rom_labels=True):
    """Name and comment a program's use of the 48K ZX Spectrum's ROM, system
    variables and hardware (call it after load()):

    - memory regions, for the list of memory locations at the top;
    - names for the system variables (e.g. 'frames'), the screen, the
      attributes and the printer buffer (only output if used); a system
      variable addressed with IY, which the ROM keeps at ERR_NR's address, is
      written as e.g. '(iy+flags-err_nr)' (unless the code sets IY to
      something else);
    - RST $08 (an error), whose error number follows it, with the report in
      a comment, e.g. 'Report 6 Number too big';
    - RST $28 (the floating point calculator), and calls to GEN-ENT-1 and
      GEN-ENT-2, followed by the calculator's bytecode, which is classified
      and commented (e.g. 'multiply'), up to an end-calc, after which the
      code continues;
    - RST $10, commented with what's printed when A is known (e.g. "Print
      'A'");
    - with rom_labels (the default), names for the ROM's routines (e.g.
      'cls'), and calls to the commonly used ones commented (e.g. 'Clear the
      screen');
    - the ULA's port, $FE, named 'ula_port', with what's written to it (the
      border colour etc.) and the keyboard half rows read from it commented
      when they're known.
    """
    cpu = session.current().cpu
    if not isinstance(cpu, cpuz80.CpuZ80):
        utils.die("spectrum.spectrum48(): call load(..., \"z80\") first")
    extras = session.current().extras
    if _set_up_done():
        utils.die("spectrum.spectrum48(): this session's machine has already been chosen")
    extras["spectrum.machine"] = "48k"
    extras["spectrum.rom_labels"] = rom_labels

    for start, end, name in regions:
        memory_region(start, end, name)
    for addr, name, base in location_names(rom_labels):
        optional_label(addr, name, base)

    for addr, hook in _DATA_CALLS.items():
        cpu.subroutine_hooks[RuntimeAddr(addr)] = hook

    if rom_labels:
        for routine in rom_routines:
            subroutine(routine.addr, rom_names[routine.addr], routine.title, None, routine.on_entry, routine.on_exit,
                       hook=print_hook if routine.addr == 0x0010 else None, is_entry_point=False)

    cpu.code_analysis_fns.append(_analysis)


# ************************************************************************************************
# The ROM

# The ROM's kinds of table, for rom(), and for a disassembly of another ROM
# with the same kinds (e.g. a replacement ROM)

def offset_entry(addr, code=True):
    """A byte at addr that's the offset from itself to code (as in the ROM's
    tables of routines, e.g. 'DEFB L0A5F - $'), or to data if not 'code'.
    Returns the address it gives."""
    target = addr + get_u8_runtime(addr)
    byte(addr)
    expr(addr, (entry(target) if code else get_label(target, addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)) + " - $")
    return target

def offset_table(addr, n):
    """n offsets to code (see offset_entry())."""
    for i in range(n):
        offset_entry(addr + i)

def keyed_offset_table(addr, n=None):
    """Pairs of a character and an offset to code (see offset_entry()),
    ending with a zero (or after n pairs)."""
    count = 0
    while (n is None and get_u8_runtime(addr) != 0) or (n is not None and count < n):
        byte(addr)
        offset_entry(addr + 1)
        addr += 2
        count += 1
    if n is None:
        byte(addr)

def syntax_table(addr, routine_classes=(0x00, 0x03, 0x05), last_classes=(0x02, 0x07, 0x0b)):
    """A command's parameter table (see the offset table at $1A48): class
    numbers (0 to $0B) and separators, until a class in routine_classes (0,
    3 or 5, each followed by the address of the command's routine) or in
    last_classes (2 for LET, 7 or $0B, which have none)."""
    while True:
        c = get_u8_runtime(addr)
        byte(addr)
        addr += 1
        if c in routine_classes:
            code_ptr(addr)
            return
        if c in last_classes:
            return

def _with_terminator(c):
    return True

def stringhi_list(addr, end):
    """Text from addr to end, each item ending with a character with bit 7
    set."""
    while addr < end:
        addr = stringhi(addr, _with_terminator)

def rom():
    """For a disassembly of the 48K Spectrum's ROM (loaded at 0, after
    spectrum48()): trace its code from the restarts, the interrupt and the
    NMI, and from its tables of routines (the control characters', the
    editing keys', the channels', the BASIC commands' and their parameter
    classes', the scanning functions' and the calculator's); classify its
    data (the tokens, the messages, the calculator's constants and the
    character set); and name every routine and table, whether it's used or
    not."""
    if not _set_up_done():
        utils.die("spectrum.rom(): call spectrum48() first")

    # The restarts, the interrupt and the NMI
    for addr in (0x0000, 0x0008, 0x0010, 0x0018, 0x0020, 0x0028, 0x0030, 0x0038, 0x0066):
        entry(addr)

    # The tables of routines
    offset_table(0x0a11, 18)                    # the control characters'
    offset_table(0x0fa0, 9)                     # the editing keys'
    for addr in (0x15af, 0x15b4, 0x15b9, 0x15be):   # the initial channel information
        code_ptr(addr)                          # (output and input routines,
        code_ptr(addr + 2)                      # then the channel's letter)
        byte(addr + 4)
    byte(0x15c3)                                # (the end marker)
    keyed_offset_table(0x162d)                  # the channels'
    keyed_offset_table(0x1716, 3)               # for CLOSE
    keyed_offset_table(0x177a)                  # for OPEN
    syntax_tables = set()
    for i in range(50):                         # the commands' parameter tables
        table = offset_entry(0x1a48 + i, code=False)
        if table not in syntax_tables:
            syntax_tables.add(table)
            syntax_table(table)
    offset_table(0x1c01, 12)                    # the parameter classes'
    keyed_offset_table(0x2596)                  # the scanning functions'
    for i in range(66):                         # the calculator's
        code_ptr(0x32d7 + 2 * i)

    # Code whose address is loaded into a register, to be pushed as a return
    # address or stored as a channel's routine (each the address of an
    # instruction's operand)
    for operand_addr in (0x04c3, 0x055f, 0x0a76, 0x0a7b, 0x0f31, 0x1109, 0x1131, 0x1566, 0x1b3e, 0x1b5b):
        expr(operand_addr, entry(get_u16_runtime(operand_addr)))

    # Routines the ROM doesn't call: zx81_name, rec_edit, not_used, free_mem
    # (for PRINT 65536-USR 7962) and p_int_sto
    for addr in (0x04aa, 0x16d4, 0x1988, 0x1f1a, 0x2d8c):
        entry(addr)

    # The tokens and messages, each ending with a character with bit 7 set
    # (some after a byte with bit 7 set, so that the first is number 1)
    byte(0x0095)
    stringhi_list(0x0096, 0x0205)               # the tokens
    byte(0x09a1)
    stringhi_list(0x09a2, 0x09f4)               # the tape messages
    byte(0x0cf8)
    stringhi(0x0cf9, _with_terminator)          # "scroll?"
    byte(0x1391)
    stringhi_list(0x1392, 0x1537)               # the error reports
    stringhi(0x1537, _with_terminator)          # ", "
    byte(0x1539)                                # (the copyright sign)
    stringhi(0x153a, _with_terminator)          # " 1982 Sinclair Research Ltd"

    # The calculator's constants
    addr = 0x32c5
    for _ in range(5):
        addr = calculator_number(addr)

    # The character set, $20 to $7F, 8 bytes each ($60 is the pound sign, and
    # $7F the copyright sign)
    for i in range(0x60):
        addr = 0x3d00 + 8 * i
        picture_binary(addr, 8)
        byte(addr, 8, cols=1)
        comment(addr, character_description(0x20 + i), inline=True)

    # Every routine and table is named, whether it's used or not
    for addr in sorted(rom_names):
        label(addr, rom_names[addr])
