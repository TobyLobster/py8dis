"""
Acorn Atom

Knowledge of the Acorn Atom (1980) and its operating system. A control file
calls acorn.atom() after load(..., "6502") (see docs/machines/acorn.md),
which calls atom() here. It:
- names the OS's entry points (OSWRCH, OSRDCH, OSLOAD etc., at #FFCB-#FFF7),
  each with a subroutine hook that comments the calls to it, e.g. 'Write
  character 65' or 'Open file for input (C=1)';
- comments what code writes with OSWRCH, OSASCI and OSCRLF, however A is
  set: runs of printable characters (e.g. 'Print "HELLO"') and the control
  codes OSWRCH acts on (e.g. 'Clear the screen'), as an analysis hook;
- names the kernel routines programs call, e.g. print_hex at #F802, whose
  calls are commented with their titles, and marks the string after a call
  to #F7D1, which prints it and carries on at the first byte with bit 7
  set;
- names the vectors at #0200-#021F, and follows the code that sets them:
  the handler is named and traced (an effect pattern, as on the BBC Micro);
- recognises loops that print a message or a character with OSWRCH;
- comments what code writes to the 8255's ports (e.g. 'Select graphics mode
  4 (256x192, 2 colours)' for #B000, 'Toggle the speaker' for #B002), and
  its tests of their input bits (e.g. 'Test the REPT key'), as an analysis
  hook (comment_hardware());
- names some OS and BASIC workspace, the hardware (the 8255 PPI at #B000,
  the VIA at #B800 and the ROM latch at #BFFF, which are I/O) and the
  regions of memory.

basic_program() (acorn.atom_basic_program()) marks an Atom BASIC program,
listing its lines in comments.

The Atom's OS is a different design from the BBC Micro's MOS, so this module
shares only a few helpers with acorn.py (in acornhelpers.py). Its data is in
acornatomtables.py.

The hooks are called once the code has been traced (see acorn.py's
docstring for the 'optimistic' and 'pessimistic' CPU states they're given).
"""

from commands import *
import config
import cpu6502
import disassembly
import memorymanager
import movemanager
import session
import utils
from align import Align
from memorymanager import BinaryAddr, BinaryLocation, RuntimeAddr
from snippets6502 import register_snippet
from snippethelper import vector_pattern, vector_handler, vector_handler_name, comment_vector, half_set_vector_text
from acornhelpers import os_call_name, character_streams, register_print_snippets

# The data tables, which control files can use as e.g. acornatom.atom_vectors
from acornatomtables import *

# OSWRCH's address on the Atom
ATOM_OSWRCH = 0xfff4

# The kernel routine that prints the string after the JSR (see atom())
ATOM_PRINT_INLINE_STRING = 0xf7d1


# ************************************************************************************************
# The subroutine hooks for the OS calls, each called with the address of a
# call, the CPU state before it, and the subroutine.Subroutine for the OS
# call.

def _known_a(state):
    """A's value before a call if it's known for certain (from an immediate
    load, or otherwise known), else None."""
    a_addr = state.pessimistic['a'].get_previous_load_imm_operand()
    return memory_binary[a_addr] if a_addr is not None else state.pessimistic['a'].value

def _known_y(state):
    """Y's value before a call if it's known for certain, else None."""
    y_addr = state.pessimistic['y'].get_previous_load_imm_operand()
    return memory_binary[y_addr] if y_addr is not None else state.pessimistic['y'].value

def _comment_where_set(state, reg, text):
    """Comment where the register 'reg' was last set before the call (if
    it's known, optimistically), e.g. 'Y=file handle'."""
    adjust_addr = state.optimistic[reg].previous_adjust
    if adjust_addr is not None:
        auto_comment(movemanager.b2r(adjust_addr), text, align=Align.INLINE)

def _comment_next_use(state, reg, text):
    """Comment where the register 'reg' is next used after the call, e.g.
    'A=character read'."""
    if state.next_use[reg] is not None:
        auto_comment(movemanager.b2r(state.next_use[reg]), text, align=Align.INLINE)

def oswrch_hook(runtime_addr, state, subroutine):
    """OSWRCH (#FFF4) and OSASCI (#FFE9): write the character in A. Comments
    the call, e.g. 'Write character 65' if A is known for certain, or for
    OSASCI with A=13 (which writes LF and CR) as OSCRLF. (The comments
    before the code, e.g. 'Print "HELLO"', are comment_characters()'s.)"""
    value = _known_a(state)
    if value is not None and subroutine.label_name.lower() == "osasci" and value == 13:
        oscrlf_hook(runtime_addr, state, subroutine)
        return
    text = "Write character" if value is None else "Write character {0}".format(value)
    auto_comment(runtime_addr, text, align=Align.INLINE)

def oscrlf_hook(runtime_addr, state, subroutine):
    """OSCRLF (#FFED): comment the call."""
    auto_comment(runtime_addr, "Write newline (characters 10 and 13)", align=Align.INLINE)

def osrdch_hook(runtime_addr, state, subroutine):
    """OSRDCH (#FFE3): read a character into A. Comments the call, and where
    A is next used."""
    auto_comment(runtime_addr, "Read a character", align=Align.INLINE)
    _comment_next_use(state, 'a', "A=character read")

def osecho_hook(runtime_addr, state, subroutine):
    """OSECHO (#FFE6): read a character into A and write it (CR as a new
    line). Comments the call, and where A is next used."""
    auto_comment(runtime_addr, "Read a character and write it", align=Align.INLINE)
    _comment_next_use(state, 'a', "A=character read")

def oscli_hook(runtime_addr, state, subroutine):
    """OSCLI (#FFF7): run the command in the input buffer at #0100 (ending
    with CR). Comments the call."""
    auto_comment(runtime_addr, "Run the command in the input buffer", align=Align.INLINE)

def osload_hook(runtime_addr, state, subroutine):
    """OSLOAD (#FFE0): load a file, with X the zero page address of its
    parameter block (the name's address, the address to load at, and a
    flag: bit 7 clear to load at the file's own address). Comments the call
    and where X is set."""
    auto_comment(runtime_addr, "Load a file", align=Align.INLINE)
    _comment_where_set(state, 'x', "X=zero page address of the load parameter block")

def ossave_hook(runtime_addr, state, subroutine):
    """OSSAVE (#FFDD): save a file, with X the zero page address of its
    parameter block (the name's address, the reload and execution
    addresses, and the start and end + 1 of the data). Comments the call
    and where X is set."""
    auto_comment(runtime_addr, "Save a file", align=Align.INLINE)
    _comment_where_set(state, 'x', "X=zero page address of the save parameter block")

def osfind_hook(runtime_addr, state, subroutine):
    """OSFIND (#FFCE): open a file, for input with the carry set, or for
    output with it clear, with X the zero page address of the name's
    address. Comments the call (with which, if the carry is known for
    certain), where X is set, and where the handle returned in A (0 if the
    file isn't found) is next used."""
    # (The carry is True or False, or 1 or 0, if it's known, or None or
    # 'pending')
    carry = state.pessimistic['c']
    if carry in (True, False):
        text = "Open file for input (C=1)" if carry else "Open file for output (C=0)"
    else:
        text = "Open a file (for input if C=1, output if C=0)"
    auto_comment(runtime_addr, text, align=Align.INLINE)
    _comment_where_set(state, 'x', "X=zero page address of the file name's address")
    _comment_next_use(state, 'a', "A=file handle (or zero if not found)")

def osshut_hook(runtime_addr, state, subroutine):
    """OSSHUT (#FFCB): close the file whose handle is in Y, or all of them
    if Y=0. Comments the call and where Y is set."""
    y = _known_y(state)
    if y == 0:
        auto_comment(runtime_addr, "Close all files (Y=0)", align=Align.INLINE)
    else:
        auto_comment(runtime_addr, "Close file Y", align=Align.INLINE)
        _comment_where_set(state, 'y', "Y=file handle")

def osbget_hook(runtime_addr, state, subroutine):
    """OSBGET (#FFD4): read a byte into A from the file whose handle is in Y.
    Comments the call, where Y is set and where A is next used."""
    auto_comment(runtime_addr, "Read a byte from file Y", align=Align.INLINE)
    _comment_where_set(state, 'y', "Y=file handle")
    _comment_next_use(state, 'a', "A=byte read")

def osbput_hook(runtime_addr, state, subroutine):
    """OSBPUT (#FFD1): write the byte in A to the file whose handle is in Y.
    Comments the call (with A's value, if it's known for certain) and where
    Y is set."""
    value = _known_a(state)
    a = "A" if value is None else "A={0}".format(value)
    auto_comment(runtime_addr, "Write byte {0} to file Y".format(a), align=Align.INLINE)
    _comment_where_set(state, 'y', "Y=file handle")

def osrdar_hook(runtime_addr, state, subroutine):
    """OSRDAR (#FFDA): read a file's arguments (with a disc filing system; on
    cassette, an error). Comments the call."""
    auto_comment(runtime_addr, "Read a file's arguments", align=Align.INLINE)

def osstar_hook(runtime_addr, state, subroutine):
    """OSSTAR (#FFD7): store a file's arguments (with a disc filing system;
    on cassette, an error). Comments the call."""
    auto_comment(runtime_addr, "Store a file's arguments", align=Align.INLINE)

# The hook for each OS call, by name (see atom_os_calls)
_OS_CALL_HOOKS = {
    "osshut": osshut_hook,
    "osfind": osfind_hook,
    "osbput": osbput_hook,
    "osbget": osbget_hook,
    "osstar": osstar_hook,
    "osrdar": osrdar_hook,
    "ossave": ossave_hook,
    "osload": osload_hook,
    "osrdch": osrdch_hook,
    "osecho": osecho_hook,
    "osasci": oswrch_hook,
    "oscrlf": oscrlf_hook,
    "oswrch": oswrch_hook,
    "oscli":  oscli_hook,
}


# ************************************************************************************************
# What code writes with OSWRCH

# The calls that write characters: their addresses, and the characters each
# writes (None for A's): OSWRCH and OSASCI write A (OSASCI writes 13 as LF
# and CR, which comment_characters() allows for), and OSCRLF writes LF and
# CR. (OSECHO writes the character it reads, so it's another call.)
_ATOM_WRITE_CALLS = {ATOM_OSWRCH: [None], 0xffe9: [None], 0xffed: [10, 13]}

def _print_text(chars):
    """A comment for printable characters (all known numbers), e.g. 'Print
    "Hello"', or 'Print characters 72, 201' if any isn't printable ASCII or
    is a double quote (which can't go in the quotes)."""
    if all(32 <= c < 127 and c != 34 for c in chars):
        return 'Print "{0}"'.format("".join(chr(c) for c in chars))
    return "Print characters {0}".format(", ".join(str(c) for c in chars))

def comment_characters():
    """Comment what the code writes with OSWRCH, OSASCI and OSCRLF, however A
    is set (see acornhelpers.character_streams()): runs of two or more
    printable characters (e.g. 'Print "HELLO"'), and the control codes
    OSWRCH acts on (e.g. 'Clear the screen'; see atom_control_codes), with
    CR and LF together, or OSASCI's CR, as 'Start a new line'. The Atom's
    control codes take no parameters, so each character is read on its own.
    (Run once the code has been traced, as an analysis hook.)

    Each comment goes on a line of its own before the code that sets up the
    character. A single printable character isn't commented here, since
    OSWRCH's hook already says e.g. 'Write character 65'."""
    moves = session.current().moves.move_id_for_binary_addr

    def comment(binary_addr, text):
        """Comment the code at binary_addr, in the move it's in."""
        disassembly.comment_binary(BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

    for stream in character_streams(_ATOM_WRITE_CALLS):
        chars = [c.char for c in stream]
        printable = []      # the indexes of the run of printable characters so far

        def end_printable():
            """Comment the run of printable characters so far, if there are
            two or more, and start a new run."""
            if len(printable) >= 2:
                comment(stream[printable[0]].start, _print_text([chars[i] for i in printable]))
            printable.clear()

        i = 0
        while i < len(chars):
            code = chars[i]
            if not isinstance(code, int):
                end_printable()
                i += 1
                continue
            if code >= 32 and code != 127:
                printable.append(i)
                i += 1
                continue
            end_printable()
            target = stream[i].target
            if target == 0xffed:
                # (OSCRLF, whose hook comments it)
                pass
            elif code == 13 and target == 0xffe9:
                # (OSASCI writes CR as a new line)
                comment(stream[i].start, "Start a new line")
            elif code in (10, 13) and i + 1 < len(chars) and chars[i + 1] == 23 - code and stream[i + 1].target != 0xffed:
                # CR and LF, or LF and CR (23 - code is the other one), as
                # one comment
                comment(stream[i].start, "Start a new line")
                i += 1
            elif code in atom_control_codes:
                comment(stream[i].start, atom_control_codes[code])
            i += 1
        end_printable()


# ************************************************************************************************
# The 8255 PPI's ports: what code writes to them, and tests of their inputs

_PORT_A = 0xb000        # the 6847's mode, and the keyboard row
_PORT_C = 0xb002        # the tape, speaker and colour set
_PPI_CONTROL = 0xb003   # the 8255's modes, or set or clear a bit of port C

def _sentence(phrases):
    """The phrases (each starting with a capital) as one, e.g. 'Speaker high,
    select colour set 0', or None if there are none."""
    if not phrases:
        return None
    return ", ".join([phrases[0]] + [p[0].lower() + p[1:] for p in phrases[1:]])

def _port_a_text(set_mask, clear_mask):
    """What a write to #B000 selects, given the bits known to be set and
    cleared (see comment_hardware()): the 6847's mode, from bits 4-7 (text
    mode if bit 4 is clear, or a graphics mode, see atom_graphics_modes, if
    all four are known), and the keyboard row, from bits 0-3 (if they're all
    known, and it isn't row 0 after the mode), e.g. 'Select graphics mode 4
    (256x192, 2 colours)' or 'Select text mode, keyboard row 5'. None if
    neither is known."""
    known = set_mask | clear_mask
    parts = []
    mode_known = False
    if clear_mask & 0x10:
        parts.append("text mode")
        mode_known = True
    elif set_mask & 0x10 and known & 0xe0 == 0xe0:
        parts.append(atom_graphics_modes[(set_mask >> 5) & 7])
        mode_known = True
    if known & 0x0f == 0x0f and (set_mask & 0x0f or not mode_known):
        parts.append("keyboard row {0}".format(set_mask & 0x0f))
    if not parts:
        return None
    return "Select " + ", ".join(parts)

def _port_c_text(set_mask, clear_mask, toggle_mask):
    """What a write to #B002 does to its output bits (see
    atom_port_c_outputs), given the bits known to be set, cleared and
    toggled (see comment_hardware()), e.g. 'Toggle the speaker', or None if
    none of them is known."""
    phrases = []
    for bit, (set_text, clear_text, toggle_text) in sorted(atom_port_c_outputs.items()):
        if toggle_mask & (1 << bit):
            phrases.append(toggle_text)
        elif set_mask & (1 << bit):
            phrases.append(set_text)
        elif clear_mask & (1 << bit):
            phrases.append(clear_text)
    return _sentence(phrases)

def _ppi_control_text(value):
    """What writing 'value' to #B003, the 8255's control register, does. With
    bit 7 set, it sets the ports' modes, e.g. 'Set the 8255's modes: port A
    output, port B input, port C bits 4-7 input, bits 0-3 output'; with it
    clear, it sets or clears a bit of port C (bit 0: set; bits 1-3: which),
    e.g. 'Set port C bit 2 (speaker high)'."""
    if value & 0x80:
        def direction(bit):
            return "input" if value & bit else "output"
        return "Set the 8255's modes: port A {0}, port B {1}, port C bits 4-7 {2}, bits 0-3 {3}".format(
            direction(0x10), direction(0x02), direction(0x08), direction(0x01))
    bit = (value >> 1) & 7
    text = "{0} port C bit {1}".format("Set" if value & 1 else "Clear", bit)
    if bit in atom_port_c_outputs:
        what = atom_port_c_outputs[bit][0 if value & 1 else 1]
        text += " ({0})".format(what[0].lower() + what[1:])
    return text

def comment_hardware():
    """Comment what the code writes to the 8255's ports, and its tests of
    their input bits (see the tables in acornatomtables.py):
    - a store to #B000 (port A), #B002 (port C) or #B003 (the control
      register) of a known value, or to #B000 or #B002 after 'lda port',
      then 'ora #n', 'and #n' and 'eor #n' (which set, clear and toggle
      bits), e.g. 'Select graphics mode 4 (256x192, 2 colours)', 'Select
      keyboard row 3', 'Toggle the speaker', 'Select colour set 1' or 'Set
      port C bit 2 (speaker high)';
    - 'inc #B000': 'Select the next keyboard row';
    - 'bit #B001' or 'bit #B002': bit 7 (N) for a BPL or BMI after it, e.g.
      'Test the field sync', bit 6 (V) for a BVC or BVS, the bits in A (if
      it's known) for a BEQ or BNE, or otherwise both, e.g. 'Test the field
      sync (N) and the REPT key (V)';
    - 'lda #B001' or 'lda #B002' then 'and #n', testing known input bits,
      e.g. 'Test the CTRL key'.
    A value is known only if it's known for certain (the pessimistic CPU
    state). (Run once the code has been traced, as an analysis hook.)"""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    moves = session.current().moves.move_id_for_binary_addr

    def comment(binary_addr, text):
        """Comment the instruction at binary_addr, in the move it's in."""
        disassembly.comment_binary(BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text,
                                   align=Align.INLINE, auto_generated=True)

    def absolute(binary_addr):
        """The 16-bit operand of the instruction at binary_addr."""
        return memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]

    for run in cpu.straight_runs():
        for k, binary_addr in enumerate(run):
            opcode = memory_binary[binary_addr]
            if opcode in (0x8d, 0x8e, 0x8c) and absolute(binary_addr) in (_PORT_A, _PORT_C, _PPI_CONTROL):
                # STA, STX or STY to a port: work out which bits are known
                # to be set, cleared and toggled
                register = absolute(binary_addr)
                set_mask = clear_mask = toggle_mask = 0
                value = None
                # 'lda register', then 'ora #n', 'and #n' and 'eor #n', then
                # 'sta register'
                i = k - 1
                while opcode == 0x8d and i >= 0 and memory_binary[run[i]] in (0x09, 0x29, 0x49):
                    i -= 1
                if register != _PPI_CONTROL and opcode == 0x8d and 0 <= i < k - 1 and memory_binary[run[i]] == 0xad and absolute(run[i]) == register:
                    for j in range(i + 1, k):
                        n = memory_binary[run[j] + 1]
                        if memory_binary[run[j]] == 0x09:
                            # ORA sets the bits
                            set_mask |= n
                            clear_mask &= ~n
                            toggle_mask &= ~n
                        elif memory_binary[run[j]] == 0x29:
                            # AND clears the others
                            clear_mask |= ~n & 0xff
                            set_mask &= n
                            toggle_mask &= n
                        else:
                            # EOR flips the bits: a known one changes, and
                            # an unknown one is toggled (or untoggled)
                            set_mask, clear_mask = (set_mask & ~n) | (clear_mask & n), (clear_mask & ~n) | (set_mask & n)
                            toggle_mask ^= n & ~(set_mask | clear_mask)
                elif k > 0 and cpu.cpu_states[run[k - 1]] is not None:
                    # A known value (of the register stored, from the state
                    # after the instruction before the store)
                    value = cpu.cpu_states[run[k - 1]].pessimistic["axy"[(0x8d, 0x8e, 0x8c).index(opcode)]].value
                    if value is None:
                        continue
                    set_mask, clear_mask = value, ~value & 0xff
                else:
                    continue
                if register == _PORT_A:
                    text = _port_a_text(set_mask, clear_mask)
                elif register == _PORT_C:
                    text = _port_c_text(set_mask, clear_mask, toggle_mask)
                else:
                    text = _ppi_control_text(value)
                if text is not None:
                    comment(binary_addr, text)
            elif opcode == 0xee and absolute(binary_addr) == _PORT_A:
                # 'inc #B000'
                comment(binary_addr, "Select the next keyboard row")
            elif opcode == 0x2c and absolute(binary_addr) in atom_port_inputs:
                # 'bit port': N is bit 7 and V bit 6, and Z is set if none of
                # the bits set in A is set in the port. What it tests depends
                # on the branch after it, if there is one.
                bits = atom_port_inputs[absolute(binary_addr)]
                following = memory_binary[run[k + 1]] if k + 1 < len(run) else None
                if following in (0x10, 0x30):
                    # BPL or BMI
                    text = "Test " + bits[7]
                elif following in (0x50, 0x70):
                    # BVC or BVS
                    text = "Test " + bits[6]
                elif following in (0xd0, 0xf0):
                    # BNE or BEQ: the bits in A, if it's known for certain
                    a = cpu.cpu_states[run[k - 1]].pessimistic['a'].value if k > 0 and cpu.cpu_states[run[k - 1]] is not None else None
                    names = None if a is None else [bits[bit] for bit in range(8) if a & (1 << bit) and bit in bits]
                    if not names or any(a & (1 << bit) and bit not in bits for bit in range(8)):
                        continue
                    text = "Test " + " and ".join(names)
                else:
                    text = "Test {0} (N) and {1} (V)".format(bits[7], bits[6])
                comment(binary_addr, text)
            elif opcode == 0x29 and k > 0 and memory_binary[run[k - 1]] == 0xad and absolute(run[k - 1]) in atom_port_inputs:
                # 'lda port : and #n', testing bits (only if every bit tested
                # is one it knows)
                bits = atom_port_inputs[absolute(run[k - 1])]
                n = memory_binary[binary_addr + 1]
                names = [bits[bit] for bit in range(8) if n & (1 << bit) and bit in bits]
                if names and all(n & (1 << bit) == 0 or bit in bits for bit in range(8)):
                    comment(binary_addr, "Test " + " and ".join(names))


# ************************************************************************************************
# Code that sets one of the vectors

def pre_trace_writing_to_atom_vector(p):
    """Code setting one of the Atom's vectors (an effect pattern, see
    snippethelper.vector_pattern()): before tracing, if both bytes are set
    to known values, label the handler (e.g. 'handle_wrcvec', then
    'handle_wrcvec_2' etc, unless it has a name already) and trace it."""
    vector = p.binding('vector')
    name = atom_vectors[vector][0]
    counts = session.current().extras.setdefault("acorn.atom_vector_handler_count", {})

    # (Called by vector_handler() only if the handler hasn't a name already)
    def new_name():
        if vector not in counts:
            counts[vector] = 2
            return "handle_{0}".format(name)
        counts[vector] += 1
        return "handle_{0}_{1}".format(name, counts[vector] - 1)

    vector_handler(p, new_name)

def post_trace_writing_to_atom_vector(p):
    """Code setting one of the Atom's vectors: after tracing, comment it (e.g.
    "Set write character vector to 'handle_wrcvec'", or for one with only one
    byte set to a known value, "Set the low byte of BRK vector to #00"), and
    write the handler's address as its name's low and high bytes."""
    description = atom_vectors[p.binding('vector')][1]
    if p.matched('lo') and p.matched('hi'):
        name = vector_handler_name(p.value('lo_value') + 256 * p.value('hi_value'))
        text = "Set {0} to '{1}'".format(description, name)
    else:
        text = half_set_vector_text(p, description, config.get_assembler().hex2)
    comment_vector(p, text)


# ************************************************************************************************
# BASIC programs

# Where Atom BASIC programs start (the text space, at ?18 * 256)
ATOM_BASIC_START = 0x2900

def _basic_lines(runtime_addr):
    """The lines of the Atom BASIC program at runtime_addr, as a list of
    (address, line number, text bytes), and the address of the byte with bit
    7 set that ends it; or None if there isn't a valid BASIC program there.

    Atom BASIC isn't tokenised: a program is a CR, then each line's number
    (high byte first), its text and a CR, ending with a byte with bit 7 set
    where the next line's number would be (#FF; NEW puts it in the first
    line's place, and OLD clears it). It's valid if all of it is loaded,
    and there are at most 10000 lines, each at most 255 characters long."""
    def u8(addr):
        """The byte at a runtime address, or None if it isn't loaded."""
        if addr > 0xffff:
            return None
        binary_addr, _ = movemanager.r2b(RuntimeAddr(addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            return None
        return memory_binary[binary_addr]

    if u8(runtime_addr) != 13:
        return None
    lines = []
    addr = runtime_addr + 1
    while True:
        high = u8(addr)
        if high is None:
            return None
        if high & 0x80:
            return lines, addr
        low = u8(addr + 1)
        if low is None or len(lines) >= 10000:
            return None
        text = []
        a = addr + 2
        while True:
            c = u8(a)
            if c is None or len(text) > 255:
                return None
            if c == 13:
                break
            text.append(c)
            a += 1
        lines.append((addr, high * 256 + low, text))
        addr = a + 1

def _basic_line_text(text):
    """A line's text (its bytes) as a listing, with the characters that aren't
    printable ASCII as e.g. {#80} (in the assembler's hex)."""
    return "".join(chr(c) if 32 <= c < 127 else "{%s}" % config.get_assembler().hex2(c) for c in text)

def _link_address(text):
    """The address after the first LINK in a line's text (outside quotes),
    as # and hex digits or as decimal digits, or None."""
    s = bytes(text).decode("latin-1")
    in_quotes = False
    for i, c in enumerate(s):
        if c == '"':
            in_quotes = not in_quotes
        elif not in_quotes and s.startswith("LINK", i):
            rest = s[i + 4:].lstrip(" ")
            if rest.startswith("#"):
                digits = ""
                for d in rest[1:]:
                    if d not in "0123456789ABCDEF":
                        break
                    digits += d
                return int(digits, 16) if digits else None
            digits = ""
            for d in rest:
                if not d.isdigit():
                    break
                digits += d
            return int(digits) if digits else None
    return None

def basic_program(runtime_addr=ATOM_BASIC_START):
    """Classify the Atom BASIC program at runtime_addr (by default #2900,
    where BASIC's text space starts), e.g. one loaded with load_atm(). The CR
    it starts with is labelled 'basic_start', and each line is labelled
    (e.g. 'basic_line_10'), with its line number as two bytes (high byte
    first, in decimal), its text as a string and its CR as a byte, and
    listed in a comment, e.g. '; 10 PRINT "HELLO"'. The byte with bit 7 set
    that ends it is labelled 'basic_end'. An address that LINK calls (# and
    hex digits, or decimal) in the loaded data is an entry point, named
    'link_entry' (then 'link_entry_2' etc.) unless it already has a name.

    Returns the address after the program, or None (classifying nothing) if
    there isn't a valid BASIC program there (see _basic_lines())."""
    found = _basic_lines(runtime_addr)
    if found is None:
        return None
    lines, end = found
    labels = session.current().labels.labels

    # Each line's label, e.g. 'basic_line_10' (or 'basic_line_10_2' for a
    # second line 10)
    names = {}
    def line_name(number):
        """The label for the next line with this line number."""
        name = "basic_line_%d" % number
        names[name] = names.get(name, 0) + 1
        return name if names[name] == 1 else "%s_%d" % (name, names[name])

    label(runtime_addr, "basic_start")
    byte(runtime_addr)
    link_count = 0
    for addr, number, text in lines:
        label(addr, line_name(number))
        auto_comment(addr, "%d %s" % (number, _basic_line_text(text)))
        byte(addr, 2)
        decimal(addr, 2)
        if text:
            string(addr + 2, len(text))
        byte(addr + 2 + len(text))

        # LINK to an address in the loaded data
        link = _link_address(text)
        if link is not None and link <= 0xffff:
            binary_addr, _ = movemanager.r2b(RuntimeAddr(link))
            if binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr):
                entry(link)
                if not (link in labels and labels[link].explicit_names):
                    link_count += 1
                    label(link, "link_entry" if link_count == 1 else "link_entry_%d" % link_count)

    label(end, "basic_end")
    byte(end)
    return end + 1


# ************************************************************************************************
# The set-up

def _memory_regions():
    """Name the regions of the Atom's memory (see atom_memory_regions), to
    group the list of memory locations at the top of the output."""
    for start, end, name in atom_memory_regions:
        memory_region(start, end, name)

def atom():
    """Set up for a program for the Acorn Atom (see the module docstring):
    the OS's entry points, with hooks to comment their calls, the comments
    on what's written with OSWRCH, the kernel routines (and the string after
    a call to #F7D1), the vectors and the code that sets them, the print
    loops, the workspace, the hardware (and the comments on what's written
    to it) and the memory regions. The names
    are optional labels, so they're only in the output if the program uses
    them, and the entry points aren't traced.

    Call it after load(..., "6502") (or "65C02"). It stops with an error if
    the CPU isn't a 6502, or if the session's machine has already been
    chosen (with atom(), or acorn.bbc() etc.). After this, config.set_upper_case_os_calls() can't be changed (it
    stops with an error), since the OS calls have been named."""
    cpu = session.current().cpu
    if not isinstance(cpu, cpu6502.Cpu6502):
        utils.die("acorn.atom(): call load(..., \"6502\") first")
    extras = session.current().extras
    # (acorn.bbc() etc. register the MOS's snippets)
    if extras.get("acorn.atom") or extras.get("acorn.snippets_registered"):
        utils.die("acorn.atom(): this session's machine has already been chosen")
    extras["acorn.atom"] = True
    # (So config.set_upper_case_os_calls() can't be called after this, since
    # the names are made now)
    extras["os_calls_named"] = True

    # The OS entry points
    for addr, name, _ in atom_os_calls:
        subroutine(addr, os_call_name(name), None, None, hook=_OS_CALL_HOOKS[name], is_entry_point=False)

    # The vectors, e.g. 'wrcvec' and 'wrcvec+1'
    for addr, (name, _) in atom_vectors.items():
        optional_label(addr, name)
        optional_label(addr + 1, name + "+1", addr)

    # The kernel routines, whose calls are commented with their titles. The
    # string after a call to #F7D1 is marked, and tracing carries on at the
    # byte with bit 7 set after it (a tracing hook, set directly, since the
    # kernel isn't usually loaded: see Cpu.subroutine_hooks).
    for addr, name, title, on_entry in atom_kernel_routines:
        subroutine(addr, name, title, None, on_entry, is_entry_point=False)
    cpu.subroutine_hooks[RuntimeAddr(ATOM_PRINT_INLINE_STRING)] = stringhi_hook

    # The workspace, e.g. 'rnd_seed' and 'rnd_seed+1'
    for addr, name, length in atom_workspace:
        optional_label(addr, name)
        for i in range(1, length):
            optional_label(addr + i, "{0}+{1}".format(name, i), addr)

    # The hardware, which is always defined as 'name = value', never inline
    io_range(0xb000, 0xc000)
    for addr, name in atom_hardware.items():
        optional_label(addr, name, definable_inline=False)

    _memory_regions()

    # The snippets: loops that print with OSWRCH, and code setting a vector
    register_print_snippets(ATOM_OSWRCH)
    register_snippet(pre_trace_writing_to_atom_vector, post_trace_writing_to_atom_vector, vector_pattern(atom_vectors))

    # The comments on what's written with OSWRCH, and to the 8255 (once the
    # code is traced)
    session.current().trace.analysis_hooks.append(comment_characters)
    session.current().trace.analysis_hooks.append(comment_hardware)
