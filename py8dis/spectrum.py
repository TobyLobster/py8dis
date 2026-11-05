"""
ZX Spectrum

ZX Spectrum specific functions: spectrum.spectrum48() names and comments a Z80
program's use of the 48K Spectrum's ROM, system variables and hardware, as
acorn.bbc() and commodore.c64() do for those machines; rom() does the rest
for a disassembly of the ROM itself.

    import spectrum
    load(0x8000, "game.bin", "z80")
    spectrum.spectrum48()

spectrum48() gives names (optional labels, output only if the program uses
them) and sets up three kinds of help, which work on what the trace finds:

- subroutine hooks (see hook_subroutine() in commands.py) for the ROM calls
  that are followed by data, not code: RST $08, followed by an error number
  (see error_hook()), and RST $28 and calls to GEN-ENT-1 and GEN-ENT-2,
  followed by the floating point calculator's bytecode (see calculator()).
  These run while the code is traced: they classify the data and say where
  the code carries on.
- unless rom_labels=False, subroutine() definitions for the commonly called
  ROM routines, so that calls to them are commented, with print_hook() for
  RST $10 to say what's printed.
- _channel_routines(), one of the Z80's code_pointer_finders (see
  CpuZ80.find_entry_points_from_effects()), which finds a channel's output
  or input routine set by the code, so that it's traced too; and
  _analysis(), one of the CPU's code_analysis_fns, run once the trace is
  done, which writes system variables addressed with IY as offsets from
  ERR_NR and names and comments the use of the ULA's port.

The functions rom() uses for the ROM's tables (offset_table(),
keyed_offset_table(), syntax_table(), stringhi_list() etc.) are there for a
disassembly of another ROM with the same kinds of table, e.g. a replacement
ROM (see examples/python/opense.py).

The names and the other data (the error reports, keywords, colours etc.)
are in spectrumtables.py. docs/machines/spectrum.md describes all this for
users.
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
    """Whether spectrum48() has been called in this session (it records the
    machine in the session's extras)."""
    return session.current().extras.get("spectrum.machine") is not None


# ************************************************************************************************
# The names

def location_names(rom_labels=True):
    """The names spectrum48() gives memory locations, as a list of
    (address, name, base address or None): one for each byte of each system
    variable (e.g. 'frames+1', with the base address of 'frames'), the
    screen, the attributes and the printer buffer, and (with rom_labels) the
    ROM's routines and tables. spectrum48() makes these optional labels,
    so they're only output if the program uses them."""
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
    """The start address of the named location that addr is in (a system
    variable, the screen, the attributes or the printer buffer), or None if
    it isn't in one. The ROM's routines and tables don't count. _analysis()
    uses this to decide whether an (IY+d) is a system variable."""
    for location in system_variables + screen_locations:
        if location.addr <= addr < location.addr + location.size:
            return location.addr
    return None


# ************************************************************************************************
# The ROM's calls followed by data: RST $08 (an error number) and RST $28
# (the calculator's bytecode)

def error_report_text(n):
    """Error report n's code and text, e.g. '6 Number too big'. n is 0 to
    27, and the codes are 0 to 9, then A to R."""
    return "%s %s" % ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[n], error_reports[n])

def error_hook(target, caller):
    """The hook for RST $08 (ERROR-1), called while tracing (see
    hook_subroutine() in commands.py) with the RST's target and the
    runtime address of the RST ('caller').

    The byte after the RST is the error number, one less than the report's
    code (so $FF is report 0, OK). This classifies it as a byte, with the
    report in a comment (e.g. 'Report 9 STOP statement'), unless it isn't
    loaded or is classified already. Returns None, since the ROM doesn't
    return from an error, so the code doesn't continue after it."""
    addr = caller + 1
    if not _loaded_and_unclassified(addr, 1):
        return None
    n = (get_u8_runtime(addr) + 1) & 0xff
    byte(addr)
    if n < len(error_reports):
        comment(addr, "Report " + error_report_text(n), inline=True)
    return None

# The floating point calculator's bytecode instructions $00 to $3D, by their
# bytes, with their names as in The Complete Spectrum ROM Disassembly (see
# calculator_op_name() for the rest, which take ranges of bytes)
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
# The instructions $A0 to $A4, which put one of the ROM's constants on the
# calculator stack
CALCULATOR_CONSTANTS = ("stk-zero", "stk-one", "stk-half", "stk-pi/2", "stk-ten")

def calculator_op_name(op):
    """The name of the calculator's bytecode instruction op (a byte), or None
    if it isn't one: a name from CALCULATOR_OPS, or, for the instructions
    that take a range of bytes, 'series-xx' ($80 to $9F, followed by xx
    numbers), a constant from CALCULATOR_CONSTANTS ($A0 to $A4),
    'st-mem-n' ($C0 to $C5, which stores in the calculator's memory area n)
    or 'get-mem-n' ($E0 to $E5, which fetches from it)."""
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
    STK-DATA reads it), and its length in bytes, as (value, length).

    The first byte's top two bits are the number of mantissa bytes, less 1
    (so 1 to 4 of them follow). Its low six bits are the exponent, less
    $50, or 0 if that's in the next byte instead. The mantissa bytes left
    out at the end are 0. That gives the calculator's usual 5 byte form:
    an exponent of 0 (e.g. a second byte of $B0, since $B0 + $50 is $100)
    is a small integer, whose first mantissa byte is the sign (0 or $FF),
    then its low and high bytes. Any other exponent is a floating point
    number: the mantissa, a fraction from 0.5 up to 1 whose top bit is
    replaced by the sign, times 2 to the power of (exponent - $80)."""
    first = get_u8_runtime(addr)
    count = (first >> 6) + 1
    exponent = first & 0x3f
    length = 1 + count
    if exponent == 0:
        exponent = get_u8_runtime(addr + 1)
        length += 1
    exponent = (exponent + 0x50) & 0xff
    # (The mantissa bytes are the last 'count' bytes, after the exponent)
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
    (see calculator_number_value()) as bytes, with its value in a comment
    (e.g. '0.5'), returning the address after it."""
    value, length = calculator_number_value(addr)
    byte(addr, length)
    comment(addr, "%.10g" % value, inline=True)
    return addr + length

def _loaded_and_unclassified(runtime_addr, length):
    """Whether the 'length' bytes at runtime_addr are loaded and not yet
    classified (as code or data). The hooks check this so that they don't
    classify bytes that aren't there, or that something else (e.g. the
    control file) has classified already."""
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
    any other end-calc it reaches is traced too (as an entry point).

    Each instruction is a byte. A jump (jump, jump-true or dec-jr-nz) is
    followed by an offset byte, written as 'label - $' since the offset is
    from the offset byte itself, and the bytecode at its target is
    classified too. stk-data is followed by a number, and series-xx by xx
    numbers (see calculator_number()). A byte that isn't an instruction
    ends the bytecode there, since it can't be bytecode after all."""
    addr = int(addr)
    todo = [addr]           # (where bytecode starts: addr, then jump targets)
    resume = []             # (the address after each end-calc reached)
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
                # (The offset is signed)
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
    # The code continues after the first end-calc (calculator_hook() returns
    # it, so that the trace carries on there), and after any others, as
    # entry points
    if not resume:
        return None
    for addr in resume[1:]:
        entry(addr)
    return resume[0]

def calculator_hook(target, caller):
    """The hook for RST $28 (FP-CALC), and for a CALL to GEN-ENT-1 or
    GEN-ENT-2 (or, in another ROM, a routine like them: see
    examples/python/opense.py), called while tracing (see hook_subroutine()
    in commands.py). The calculator's bytecode follows the instruction,
    which is 1 byte for the RST and 3 for a CALL. Returns where the code
    carries on, after the end-calc, or None (see calculator())."""
    return calculator(int(caller) + (1 if target == 0x0028 else 3))

# The ROM routines followed by data, not code, by address, with their hooks
# (spectrum48() makes them the CPU's subroutine hooks): the restarts, which
# are at the same addresses in any ROM, and GEN-ENT-1 and GEN-ENT-2, which
# are only where they are in Sinclair's ROM (so not with rom_labels=False)
_DATA_CALLS = {0x0008: error_hook, 0x0028: calculator_hook}
_ROM_DATA_CALLS = {0x335e: calculator_hook, 0x3362: calculator_hook}


# ************************************************************************************************
# Comments on the code

# The control codes with names, for character_description()
CONTROL_CODES = {
    0x06: "comma", 0x08: "cursor left", 0x0d: "ENTER", 0x10: "INK", 0x11: "PAPER",
    0x12: "FLASH", 0x13: "BRIGHT", 0x14: "INVERSE", 0x15: "OVER", 0x16: "AT", 0x17: "TAB",
}

def character_description(c):
    """A description of a character printed with RST $10, e.g. "'A'" or
    '$16 (AT)': a printable ASCII character in quotes, or else its code in
    hex with what it is in the Spectrum's character set (the pound or
    copyright sign, a control code, a block graphic, a user-defined graphic
    A to U, or a keyword's token). rom() uses it for the character set's
    comments too."""
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

# The control codes followed by parameters (the next characters printed),
# and what those are, for print_hook()'s comments. (TAB's second parameter
# is the high byte of its column.)
CONTROL_PARAMETERS = {
    0x10: ("INK's colour",), 0x11: ("PAPER's colour",), 0x12: ("FLASH's 0 or 1",), 0x13: ("BRIGHT's 0 or 1",),
    0x14: ("INVERSE's 0 or 1",), 0x15: ("OVER's 0 or 1",), 0x16: ("AT's line", "AT's column"), 0x17: ("TAB's column", "(TAB's high byte)"),
}

def print_hook(runtime_addr, state, subroutine):
    """The hook for RST $10 (PRINT-A), called for each instruction that
    calls it (see subroutine() in commands.py), with the instruction's
    runtime address, the CPU state before it and the subroutine. It
    comments the instruction with what's printed if A is known (e.g.
    "Print 'A'" or 'Print $16 (AT)'), or else with the routine's title.

    After a control code that takes parameters (e.g. AT, see
    CONTROL_PARAMETERS), the next calls are taken to be printing them (e.g.
    "Print 10 (AT's line)"), as long as each is within 16 bytes after the
    one before. The hook is called for one call at a time, in address
    order, so the parameters still to come, and the address of the call
    before, are kept in the session's extras between calls. The code at
    RST $10's own address (in a disassembly of the ROM) isn't commented."""
    if subroutine.runtime_addr == runtime_addr:
        return
    extras = session.current().extras
    previous_addr, pending = extras.get("spectrum.print_parameters", (None, ()))
    # (A parameter is only printed by a call just after the one before)
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
    """What writing value to the ULA's port does, as a comment, e.g. 'Border
    blue, MIC on': bits 0-2 are the border colour, bit 3 MIC and bit 4 the
    speaker."""
    text = "Border " + colours[value & 7]
    if value & 0x08:
        text += ", MIC on"
    if value & 0x10:
        text += ", speaker on"
    return text

def keyboard_description(high_byte):
    """Which keyboard half rows reading the ULA's port reads, as a comment,
    e.g. 'Read the keyboard (SPACE-B)', or None if it reads none. high_byte
    is the high byte of the port's address (A for 'in a,(n)', B for 'in
    r,(c)'): each half row whose bit in it is 0 is read."""
    rows = [keyboard_half_rows[i] for i in range(8) if not high_byte & (1 << i)]
    if not rows:
        return None
    return "Read the keyboard (%s)" % ", ".join(rows)

def _previous_state(cpu, binary_addr, previous_binary_addr):
    """The CPU state before the instruction at binary_addr: the state after
    the instruction at previous_binary_addr, which is the one before it, or
    None if that doesn't run on into this one (e.g. it's a jump, or data).
    If there's no instruction before, or this one has a label (so code can
    come to it from elsewhere), nothing is known: an empty CpuState."""
    runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))
    if previous_binary_addr is None or runtime_addr in session.current().labels.labels:
        return cpu.CpuState()
    return cpu.cpu_states[previous_binary_addr] or cpu.CpuState()

def _analysis():
    """The Spectrum's analysis of the code, run once it's traced and the CPU
    states are known (spectrum48() adds it to the CPU's code_analysis_fns).
    It goes through the code in address order, and for each instruction:

    - writes an (IY+d) whose address is a system variable (or the screen
      etc.) as an offset from ERR_NR's address, e.g. '(iy+flags - err_nr)',
      unless IY is known to hold something else, or d has an expression
      already;
    - in 'out (n),a' or 'in a,(n)' with the ULA's port, $FE, writes the port
      as 'ula_port' (unless it has an expression already; the constant is
      defined if any instruction uses it), and comments
      what's written (the border colour etc.) or which keyboard half rows
      are read, when A is known;
    - comments 'out (c),r' and 'in r,(c)' in the same way, when C is known
      to be even (the ULA answers any even port), from r or B."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    expressions = session.current().classifications.expressions
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = range_start
        previous = None
        while binary_addr < range_end:
            c = classification.get_classification(binary_addr)
            if not isinstance(c, cpu.Opcode):
                # (Not an instruction: the next one doesn't follow on from it)
                previous = None
                binary_addr += 1 if c is None else c.length()
                continue
            state = _previous_state(cpu, binary_addr, previous)
            runtime_addr = movemanager.b2r(BinaryAddr(binary_addr))

            # (IY+d): IY holds ERR_NR's address. (It's taken to, unless
            # either half of IY is known and isn't that half of it.)
            index = c.part(cpuz80.Index)
            if index is not None and index.register == "iy":
                iyh, iyl = state["iyh"], state["iyl"]
                d_addr = binary_addr + index.offset
                iy_is_base = iyh in (None, IY_BASE >> 8) and iyl in (None, IY_BASE & 0xff)
                if iy_is_base and d_addr not in expressions:
                    # (d is signed)
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
                # out (c),r or in r,(c), with C even (the ULA). (These are
                # ED 41 to ED 79 and ED 40 to ED 78: bits 3-5 of the second
                # byte are r, and bit 0 is 1 for OUT. 'in (c)' and 'out
                # (c),0', with no register, aren't included.)
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

            # (The next instruction follows on from this one unless this
            # ends a block, e.g. JP or RET)
            previous = binary_addr if not c.is_block_end() else None
            binary_addr += c.length()

    # Define ula_port, if any instruction uses it
    if session.current().extras.get("spectrum.ula_port_used"):
        constant(ULA_PORT, "ula_port", format=Format.HEX)


# ************************************************************************************************
# A channel's output or input routine set by the code: e.g. 'ld de,routine'
# then (perhaps after a jump or call) 'ld hl,(curchl) : ld (hl),e : inc hl :
# ld (hl),d', which sets the current channel's output routine. The routine
# is traced, and named in the 'ld de' (see CpuZ80.code_pointer_finders).

CURCHL = 0x5c51         # the address of the current channel's information
CHANS = 0x5c4f          # the address of the channels' information (5 bytes each: K, S, R, P)

# The most instructions followed from each 'ld de,nn' or 'ld hl,(curchl)'
_CHANNEL_SEARCH_LIMIT = 32

def _channel_field(variable, offset):
    """What's at 'offset' bytes from the address held in the system variable
    'variable' (CURCHL or CHANS), if it's a channel's output or input
    routine, for the comment (e.g. "the current channel's output routine"
    or "channel K's input routine"), or else None. Each channel's
    information is 5 bytes: the output routine's address, the input
    routine's and the channel's letter."""
    if variable == CURCHL:
        return {0: "the current channel's output routine", 2: "the current channel's input routine"}.get(offset)
    channel, field = divmod(offset, 5)
    if channel < 4 and field in (0, 2):
        return "channel %s's %s routine" % ("KSRP"[channel], "output" if field == 0 else "input")
    return None

def _channel_routines():
    """The channels' routines set by the code (see above), as
    CpuZ80.code_pointer_finders wants them. The code is followed from each
    'ld de,nn' and 'ld hl,(curchl)' or 'ld hl,(chans)', on through jumps
    and into calls (but not conditional ones), while it doesn't change the
    registers, until the routine's address in DE is stored to a channel's
    routine with 'ld (hl),e : inc hl : ld (hl),d'.

    Returns a list of (the 'ld de' instruction's binary address, its
    operand's binary address, the routine's address, and the comment for
    the 'ld de', with '%s' for the routine's label)."""
    cpu = session.current().cpu
    result = []
    for run in cpu.straight_runs():
        for start in run:
            # Each search starts at an 'ld de,nn', or an 'ld hl,(curchl)' or
            # 'ld hl,(chans)'
            c = classification.get_classification(start)
            if not (c.key == (0x11,) or (c.key == (0x2a,) and memorymanager.get_u16_binary(start + 1) in (CURCHL, CHANS))):
                continue
            de = None           # (the 'ld de' instruction's binary address, if DE is its value)
            hl = None           # (the system variable, and the offset from its address)
            low = None          # (where E was stored, and where DE came from)
            binary_addr = BinaryAddr(start)
            for _ in range(_CHANNEL_SEARCH_LIMIT):
                c = classification.get_classification(binary_addr)
                if not isinstance(c, cpu.Opcode):
                    break
                next_addr = BinaryAddr(binary_addr + c.length())
                if c.key == (0x11,):                                        # ld de,nn
                    de = binary_addr
                elif c.key == (0x2a,):                                      # ld hl,(nn)
                    variable = memorymanager.get_u16_binary(binary_addr + 1)
                    hl = (variable, 0) if variable in (CURCHL, CHANS) else None
                elif c.key == (0x23,):                                      # inc hl
                    hl = None if hl is None else (hl[0], hl[1] + 1)
                elif c.key == (0x73,):                                      # ld (hl),e
                    low = None if hl is None or de is None else (hl, de)
                elif c.key == (0x72,):                                      # ld (hl),d
                    # (Found, if E was stored in the byte before, from the
                    # same 'ld de'. The search ends here either way.)
                    if hl is not None and de is not None and low == ((hl[0], hl[1] - 1), de):
                        description = _channel_field(hl[0], hl[1] - 1)
                        if description is not None:
                            operand_addr = BinaryAddr(de + 1)
                            result.append((de, operand_addr, memorymanager.get_u16_binary(operand_addr), "Set " + description + " to %s"))
                    break
                elif c.kind in (cpuz80.FLOW_JP, cpuz80.FLOW_JR) or c.key == (0xcd,):   # jp nn, jr e, call nn
                    # (Followed to its target, a call as if it were a jump)
                    binary_addr = movemanager.r2b(c.target(binary_addr))[0]
                    if binary_addr is None:
                        break
                    continue
                elif c.kind != cpuz80.FLOW_NEXT or c.mnemonic == "ret":
                    break           # (Conditional, or the code goes elsewhere)
                else:
                    # Any other instruction: DE or HL is forgotten if it
                    # changes it, and the search ends if both are
                    _, writes, _ = cpu._effects(c, binary_addr)
                    if "d" in writes or "e" in writes:
                        de = None
                    if "h" in writes or "l" in writes:
                        hl = None
                    if de is None and hl is None:
                        break
                binary_addr = next_addr
    return result


# ************************************************************************************************
# The set up

def spectrum48(rom_labels=True):
    """Name and comment a program's use of the 48K ZX Spectrum's ROM, system
    variables and hardware (call it after load()):

    - memory regions, for the list of memory locations at the top;
    - names for the system variables (e.g. 'frames'), the screen, the
      attributes and the printer buffer (only output if used); a system
      variable addressed with IY, which the ROM keeps at ERR_NR's address, is
      written as e.g. '(iy+flags - err_nr)' (unless the code sets IY to
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
      when they're known;
    - a channel's output or input routine set by the code (e.g. 'ld
      de,routine : ld hl,(curchl) : ld (hl),e : inc hl : ld (hl),d'), which
      is traced, named in the 'ld de' and commented ('Set the current
      channel's output routine to routine').

    The RST $08 and RST $28 hooks are set up with rom_labels=False too (the
    restarts are at the same addresses in any ROM), but the GEN-ENT-1 and
    GEN-ENT-2 ones, and RST $10's comments, like the other ROM routines',
    aren't (a replacement ROM's routines are elsewhere: see
    examples/python/opense.py). This stops with an error if the CPU isn't the
    Z80, or if it has been called already.
    """
    cpu = session.current().cpu
    if not isinstance(cpu, cpuz80.CpuZ80):
        utils.die("spectrum.spectrum48(): call load(..., \"z80\") first")
    extras = session.current().extras
    if _set_up_done():
        utils.die("spectrum.spectrum48(): this session's machine has already been chosen")
    extras["spectrum.machine"] = "48k"
    extras["spectrum.rom_labels"] = rom_labels

    # The memory regions, and the names (optional labels)
    for start, end, name in regions:
        memory_region(start, end, name)
    for addr, name, base in location_names(rom_labels):
        optional_label(addr, name, base)

    # The ROM calls followed by data. (The hooks are set directly, not with
    # hook_subroutine(), which would also make the addresses entry points.)
    for addr, hook in _DATA_CALLS.items():
        cpu.subroutine_hooks[RuntimeAddr(addr)] = hook
    if rom_labels:
        for addr, hook in _ROM_DATA_CALLS.items():
            cpu.subroutine_hooks[RuntimeAddr(addr)] = hook

    # The commonly called ROM routines, so that calls to them are commented
    # (with what's printed, for RST $10). Their names are optional labels,
    # and they aren't made entry points.
    if rom_labels:
        for routine in rom_routines:
            subroutine(routine.addr, rom_names[routine.addr], routine.title, None, routine.on_entry, routine.on_exit,
                       hook=print_hook if routine.addr == 0x0010 else None, is_entry_point=False)

    # What's found once the code is traced
    cpu.code_analysis_fns.append(_analysis)
    cpu.code_pointer_finders.append(_channel_routines)


# ************************************************************************************************
# The ROM

# The ROM's kinds of table, for rom(), and for a disassembly of another ROM
# with the same kinds (e.g. a replacement ROM)

def offset_entry(addr, code=True):
    """Classify the byte at addr as the offset from itself to code (as in
    the ROM's tables of routines, e.g. 'DEFB L0A5F - $'), or to data if not
    'code', written as 'label - $'. The offset is unsigned, so the target
    is always after the byte. With 'code', the target is an entry point, so
    it's traced. Returns the target's address."""
    target = addr + get_u8_runtime(addr)
    byte(addr)
    expr(addr, (entry(target) if code else get_label(target, addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)) + " - $")
    return target

def offset_table(addr, n):
    """A table of n offsets to code, one byte each, from addr (see
    offset_entry())."""
    for i in range(n):
        offset_entry(addr + i)

def keyed_offset_table(addr, n=None):
    """A table of pairs of a character (e.g. a channel's letter, as a byte)
    and an offset to code (see offset_entry()), from addr. Without n, it
    ends with a zero byte, which is classified too; with n, it's n pairs,
    with no zero after them."""
    count = 0
    while (n is None and get_u8_runtime(addr) != 0) or (n is not None and count < n):
        byte(addr)
        offset_entry(addr + 1)
        addr += 2
        count += 1
    if n is None:
        byte(addr)

def syntax_table(addr, routine_classes=(0x00, 0x03, 0x05), last_classes=(0x02, 0x07, 0x0b)):
    """Classify a BASIC command's parameter table at addr (the ROM finds
    them from the offset table at $1A48), as bytes: class numbers (0 to
    $0B) and separators (e.g. '='), until a class in routine_classes (by
    default 0, 3 or 5, each followed by the address of the command's
    routine, which is classified as a code pointer, so it's traced) or in
    last_classes (by default 2, for LET, 7 or $0B, which have none). A
    replacement ROM may have other classes, e.g. OpenSE BASIC's $0C (see
    examples/python/opense.py)."""
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
    """For stringhi(): the character with bit 7 set that ends a string is
    part of it, whatever it is (as in the ROM's tokens and messages)."""
    return True

def stringhi_list(addr, end):
    """Classify the text from addr up to end as strings, each ending with a
    character with bit 7 set, which is part of it (as in the ROM's tokens
    and messages). stringhi() stops with an error if a string would start
    at a byte that's classified already."""
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
    not. The addresses are the 48K ROM's: see offset_table() etc. for
    another ROM's. This stops with an error if spectrum48() hasn't been
    called, or was called with rom_labels=False (which leaves out the 48K
    ROM's hooks for GEN-ENT-1 and GEN-ENT-2, so its calculator code wouldn't
    be traced right)."""
    if not _set_up_done():
        utils.die("spectrum.rom(): call spectrum48() first")
    if not session.current().extras["spectrum.rom_labels"]:
        utils.die("spectrum.rom(): it's for the 48K ROM, so call spectrum48() without rom_labels=False")

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

    # Return addresses pushed with 'ld hl,nn : push hl' that aren't found
    # from what the code does (see CpuZ80.pushed_return_addresses()): REPORT-G,
    # which MAIN-ADD takes off the stack again if there's room, and STMT-RET,
    # which the code returns to through the commands' parameter routines
    # (each the address of the instruction's operand)
    for operand_addr in (0x1566, 0x1b3e):
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
