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
- names some OS and BASIC workspace, the hardware (the 8255 PPI at #B000,
  the VIA at #B800 and the ROM latch at #BFFF, which are I/O) and the
  regions of memory.

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
    loops, the workspace, the hardware and the memory regions. The names
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

    # The comments on what's written with OSWRCH (once the code is traced)
    session.current().trace.analysis_hooks.append(comment_characters)
