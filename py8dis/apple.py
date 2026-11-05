"""
Apple II

Knowledge of the Apple II+ and IIe (see docs/machines/apple2.md). A control
file calls apple2() after load() (or load_apple_file() etc.). It:
- names the Monitor ROM's routines (COUT, HOME, RDKEY etc.), each with a
  subroutine hook that comments the calls to it with its title, and, where
  a register's value is known, more: e.g. "Print 'A'" for COUT, 'Print 5
  spaces' for PRBL2, 'Send output to slot 1 (PR#1)' for OUTPORT, or WAIT's
  delay;
- comments what code prints with COUT (and COUT1, CROUT etc.), however A is
  set: runs of characters (e.g. 'Print "HELLO"'), and the DOS commands
  printed after a Ctrl-D (e.g. 'DOS command: BLOAD GAME'), as an analysis
  hook; and recognises loops that print a message with COUT;
- names the Monitor's zero page (CH, CV, CSWL etc.), the input buffer (IN)
  and the page 3 vectors, and follows the code that sets a vector or the
  output or input hook (CSW, KSW): the handler is named (e.g.
  'output_handler') and traced;
- names the soft switches (KBD, SPKR, TXTCLR etc.), which are I/O, and the
  regions of memory;
- makes the Apple II's high ASCII (ASCII with bit 7 set) the session's text
  encoding (see textencoding.py).

The names are Apple's, in capitals (unless
config.set_upper_case_os_calls(False)), or with names="descriptive",
py8dis's own, e.g. 'print_char' for COUT. They're optional labels, so only
those the program uses are in the output. The data is in appletables.py.

The hooks are called once the code has been traced, with the CPU states
before the call (see acorn.py's docstring for the 'optimistic' and
'pessimistic' states).
"""

import copy

from commands import *
import config
import cpu6502
import disassembly
import mainformatter
import session
import textencoding
import utils
from align import Align
from memorymanager import BinaryAddr, BinaryLocation
from snippets6502 import register_snippet
from snippethelper import vector_pattern, vector_handler, vector_handler_name, comment_vector, half_set_vector_text
from acornhelpers import character_streams, register_print_snippets

# The data tables, which control files can use as e.g.
# apple.apple2_monitor_routines
from appletables import *

# The models apple2() knows, and the styles of names
MODELS = ("ii+", "iie")
NAMES = ("apple", "descriptive")

# The Monitor's routines that print characters
COUT = 0xfded
COUT1 = 0xfdf0
VIDOUT = 0xfbfd
CROUT = 0xfd8e
CROUT1 = 0xfd8b
BELL = 0xff3a


def official_name(name):
    """One of Apple's names (e.g. 'COUT'), in capitals unless
    config.set_upper_case_os_calls(False)."""
    return name.upper() if config.get_upper_case_os_calls() else name.lower()

def _names():
    """The session's style of names: "apple" or "descriptive"."""
    return session.current().extras.get("apple.names", "apple")

def _name(apple_name, descriptive_name):
    """The name in the session's style (Apple's, as official_name() gives
    it, or the descriptive one)."""
    return official_name(apple_name) if _names() == "apple" else descriptive_name


# ************************************************************************************************
# The subroutine hooks for the Monitor's routines, each called with the
# address of a call, the CPU state before it, and the subroutine.Subroutine

def _known(state, reg):
    """The value of the register reg ('a', 'x' or 'y') before the call, if
    it's known for certain (the pessimistic state) to have been set by an
    immediate load (e.g. 'lda #n'), else None."""
    binary_addr = state.pessimistic[reg].get_previous_load_imm_operand()
    return None if binary_addr is None else memory_binary[binary_addr]

def _hex2(n):
    """A byte in hex, as the assembler writes it, e.g. $1f."""
    return config.get_assembler().hex2(n)

def char_description(c):
    """A description of a character printed with COUT, e.g. "'A'" for a high
    ASCII character, "a carriage return" for a control character COUT acts
    on, or else its code, e.g. 'character $41'."""
    char = textencoding.APPLE.char(c)
    if char is not None:
        return "'%s'" % char
    if c in apple2_control_codes:
        return apple2_control_codes[c]
    return "character " + _hex2(c)

def _call_hook(describe, known_reg=None):
    """A hook that comments the registers (from the subroutine's on_entry and
    on_exit) and the call, as the 6502's default hook does, but with the
    text describe(value) gives for the value of the register known_reg, if
    it's known (and then without the on_entry comment for that register,
    which the text says). describe() can return None to keep the title."""
    def hook(runtime_addr, state, subroutine):
        value = _known(state, known_reg) if known_reg is not None else None
        text = describe(value) if value is not None else None
        if text is not None:
            subroutine = copy.copy(subroutine)
            subroutine.title = text
            subroutine.on_entry = {reg: description for reg, description in subroutine.on_entry.items() if reg != known_reg}
        session.current().cpu.default_subroutine_hook(runtime_addr, state, subroutine)
    return hook

def _print_hook(runtime_addr, state, subroutine):
    """COUT's, COUT1's and VIDOUT's hook: if A is known, comment the call with
    the character printed (e.g. "Print 'A'" or 'Print a carriage return'),
    and write a high ASCII character as one where A is loaded (e.g. "lda
    #'A' | $80", if the assembler can: see
    Assembler.encoded_char_literal()), unless the operand is already
    formatted or has an expression."""
    _call_hook(lambda a: "Print " + char_description(a), 'a')(runtime_addr, state, subroutine)
    a = _known(state, 'a')
    operand_addr = state.pessimistic['a'].get_previous_load_imm_operand()
    format_hint = session.current().disassembly.format_hint
    if (a is not None and textencoding.APPLE.char(a) is not None and textencoding.current() is textencoding.APPLE
            and operand_addr not in format_hint and operand_addr not in session.current().classifications.expressions):
        format_hint[operand_addr] = mainformatter.char_formatter

def wait_cycles(a):
    """The number of cycles the Monitor's WAIT takes for A (0 meaning 256),
    from the Apple II Reference Manual: (26 + 27A + 5A^2) / 2."""
    a = a or 256
    return (26 + 27 * a + 5 * a * a) // 2

def _wait_text(a):
    """WAIT's comment, e.g. 'Wait 11,117 cycles (about 10.9 ms)', at the
    Apple II's 1.023 MHz."""
    cycles = wait_cycles(a)
    return "Wait {0:,} cycles (about {1:.1f} ms)".format(cycles, cycles / 1023.0)

def _colour_text(a):
    """SETCOL's comment, e.g. 'Set the lo-res colour to 9 (orange)'."""
    if a < 16:
        return "Set the lo-res colour to {0} ({1})".format(a, apple2_lores_colours[a])
    return None

# The hooks of the routines that have their own, by address (the others
# have the 6502's default hook: see apple2_monitor_routines)
_HOOKS = {
    COUT:   _print_hook,
    COUT1:  _print_hook,
    VIDOUT: _print_hook,
    0xf94a: _call_hook(lambda x: "Print {0} spaces".format(x or 256), 'x'),                      # PRBL2
    0xfb5b: _call_hook(lambda a: "Move the cursor to row {0}".format(a), 'a'),                  # TABV
    0xfc24: _call_hook(lambda a: "Move the cursor to row {0}".format(a), 'a'),                  # VTABZ
    0xfb4b: _call_hook(lambda a: "Set the text window to the full width, from row {0} down".format(a), 'a'),  # SETWND
    0xf864: _call_hook(_colour_text, 'a'),                                                      # SETCOL
    0xfca8: _call_hook(_wait_text, 'a'),                                                        # WAIT
    0xfe8b: _call_hook(lambda a: "Take input from slot {0} (IN#{0})".format(a) if a < 8 else None, 'a'),  # INPORT
    0xfe95: _call_hook(lambda a: "Send output to slot {0} (PR#{0})".format(a) if a < 8 else None, 'a'),   # OUTPORT
    0xfb1e: _call_hook(lambda x: "Read paddle {0}".format(x) if x < 4 else None, 'x'),          # PREAD
}


# ************************************************************************************************
# What code prints with COUT

# The routines that print characters: their addresses, and the characters
# each prints (None for A's). CROUT and CROUT1 print a CR, and BELL Ctrl-G.
_PRINT_CALLS = {COUT: [None], COUT1: [None], VIDOUT: [None], CROUT: [0x8d], CROUT1: [0x8d], BELL: [0x87]}

def _quoted(text):
    """The text in double quotes, or single ones if it has a double quote in
    it."""
    return "'{0}'".format(text) if '"' in text else '"{0}"'.format(text)

def comment_printing():
    """Comment what the code prints with COUT, COUT1, VIDOUT, CROUT, CROUT1
    and BELL, however A is set (see acornhelpers.character_streams()): runs
    of two or more high ASCII characters (e.g. 'Print "HELLO"'), and a DOS
    command, a Ctrl-D followed by the command's characters (e.g. 'DOS
    command: BLOAD GAME'), which DOS takes after a carriage return. (Run once
    the code has been traced, as an analysis hook.)

    Each comment goes on a line of its own before the code that sets up the
    first character. A single character isn't commented here, since the
    call's hook already says e.g. "Print 'A'"."""
    moves = session.current().moves.move_id_for_binary_addr

    def comment(binary_addr, text):
        """Comment the code at binary_addr, in the move it's in."""
        disassembly.comment_binary(BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

    for stream in character_streams(_PRINT_CALLS):
        chars = [c.char if isinstance(c.char, int) else None for c in stream]
        i = 0
        while i < len(chars):
            # A run of high ASCII characters, after a Ctrl-D or not
            dos_command = chars[i] == 0x84
            j = i + 1 if dos_command else i
            text = ""
            while j < len(chars) and chars[j] is not None and textencoding.APPLE.char(chars[j]) is not None:
                text += textencoding.APPLE.char(chars[j])
                j += 1
            if dos_command and text:
                comment(stream[i].start, "DOS command: " + text)
            elif len(text) >= 2:
                comment(stream[i].start, "Print " + _quoted(text))
            i = max(j, i + 1)


# ************************************************************************************************
# Code that sets one of the vectors, or the output or input hook

def pre_trace_setting_vector(p):
    """Code setting one of the vectors (an effect pattern, see
    snippethelper.vector_pattern()): before tracing, if both bytes are set
    to known values, label the handler (e.g. 'output_handler', then
    'output_handler_2' etc., unless it has a name already) and trace it."""
    vector = p.binding('vector')
    name = apple2_vectors[vector][0]
    counts = session.current().extras.setdefault("apple.vector_handler_count", {})

    # (Called by vector_handler() only if the handler hasn't a name already)
    def new_name():
        counts[vector] = counts.get(vector, 0) + 1
        return name if counts[vector] == 1 else "{0}_{1}".format(name, counts[vector])

    vector_handler(p, new_name)

def post_trace_setting_vector(p):
    """Code setting one of the vectors: after tracing, comment it (e.g.
    "Set the output hook (CSW) to 'output_handler'", or for one with only
    one byte set to a known value, "Set the low byte of the reset vector to
    $00"), and write the handler's address as its name's low and high
    bytes."""
    description = apple2_vectors[p.binding('vector')][1]
    if p.matched('lo') and p.matched('hi'):
        name = vector_handler_name(p.value('lo_value') + 256 * p.value('hi_value'))
        text = "Set {0} to '{1}'".format(description, name)
    else:
        text = half_set_vector_text(p, description, config.get_assembler().hex2)
    comment_vector(p, text)


# ************************************************************************************************
# The set-up

def _routine(addr, apple_name, descriptive_name, title, on_entry, on_exit):
    """Name a ROM routine, as an optional label, with its title, registers
    and hook (its own from _HOOKS, or the 6502's default)."""
    subroutine(addr, _name(apple_name, descriptive_name), title, None, on_entry, on_exit, hook=_HOOKS.get(addr), is_entry_point=False)

def _workspace():
    """Name the workspace (see apple2_workspace and apple2_page3_vectors):
    each byte of a location of more than one byte is named from its start
    (e.g. 'IN+1', 'output_hook+1'), except that Apple's names for the high
    bytes of the Monitor's zero page pointers are their own (e.g. 'CSWH')."""
    for addr, apple_name, descriptive_name, length in apple2_workspace + apple2_page3_vectors:
        name = _name(apple_name, descriptive_name)
        optional_label(addr, name)
        for i in range(1, length):
            if _names() == "apple" and addr + i in apple2_workspace_high_bytes:
                optional_label(addr + i, official_name(apple2_workspace_high_bytes[addr + i]))
            else:
                optional_label(addr + i, "{0}+{1}".format(name, i), addr)

def apple2(model="ii+", names="apple"):
    """Set up for a program for the Apple II+ or IIe (see the module
    docstring): the Monitor's routines, with hooks to comment their calls,
    the comments on what's printed, the print loops, the zero page and other
    workspace, the vectors and the code that sets them, the soft switches,
    the memory regions, and high ASCII as the session's text encoding.

    'model' is "ii+" (the default) or "iie" (the unenhanced IIe, which adds
    its status switches and its 80-column firmware's AUXMOVE and XFER).
    'names' is "apple" for Apple's names (the default), or "descriptive".

    Call it after load(..., "6502") (or "6510"). It stops with an error if
    the CPU isn't a 6502 (the II+ and the unenhanced IIe have an NMOS
    6502), if the arguments are wrong, or if the session's machine has
    already been chosen. After this, config.set_upper_case_os_calls() can't
    be changed (it stops with an error), since the names have been made."""
    if model not in MODELS:
        utils.die("apple.apple2(): model must be one of {0}, not {1!r}".format(", ".join(repr(m) for m in MODELS), model))
    if names not in NAMES:
        utils.die("apple.apple2(): names must be one of {0}, not {1!r}".format(", ".join(repr(n) for n in NAMES), names))
    cpu = session.current().cpu
    if not isinstance(cpu, cpu6502.Cpu6502):
        utils.die("apple.apple2(): call load(..., \"6502\") first")
    if config.get_cmos():
        utils.die("apple.apple2(): the Apple II+ and IIe have a 6502, not a 65C02 (the enhanced IIe and the IIc aren't supported yet)")
    extras = session.current().extras
    if any(extras.get(key) for key in ("apple.model", "acorn.atom", "acorn.snippets_registered", "commodore.machine", "spectrum.machine")):
        utils.die("apple.apple2(): this session's machine has already been chosen")
    extras["apple.model"] = model
    extras["apple.names"] = names
    # (So config.set_upper_case_os_calls() can't be called after this, since
    # the names are made now)
    extras["os_calls_named"] = True

    config.set_text_encoding("apple")

    # The Monitor's routines (and the IIe's firmware's), and other places in
    # the ROM
    for entry_ in apple2_monitor_routines:
        _routine(*entry_)
    if model == "iie":
        for entry_ in apple2e_firmware_routines:
            _routine(*entry_)
    for addr, apple_name, descriptive_name in apple2_rom_locations:
        optional_label(addr, _name(apple_name, descriptive_name))

    _workspace()

    # The soft switches, which are always defined as 'name = value', never
    # inline
    io_range(0xc000, 0xc100)
    switches = dict(apple2_soft_switches)
    if model == "iie":
        switches.update(apple2e_soft_switches)
    for addr, (apple_name, descriptive_name) in switches.items():
        optional_label(addr, _name(apple_name, descriptive_name), definable_inline=False)

    for start, end, name in apple2_memory_regions:
        memory_region(start, end, name)

    # The snippets: loops that print with COUT, and code setting a vector
    register_print_snippets(COUT)
    register_snippet(pre_trace_setting_vector, post_trace_setting_vector, vector_pattern(apple2_vectors))

    # The comments on what's printed (once the code is traced)
    session.current().trace.analysis_hooks.append(comment_printing)
