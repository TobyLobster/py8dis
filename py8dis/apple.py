"""
Apple II

Knowledge of the Apple II+, IIe, enhanced IIe and IIc (see
docs/machines/apple2.md). A control file calls apple2() after load() (or
load_apple_file() etc.). It:
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
- names the soft switches (KBD, SPKR, TXTCLR etc.) and the language card's
  (LCBANK2 etc.), which are I/O, and the regions of memory;
- comments what the code does with them, e.g. 'Show graphics', 'Click the
  speaker', 'Wait for a key' or 'Language card: read and write RAM bank 2
  (two reads in a row enable writing)', as an analysis hook; and names the
  IIe's switches that act when written (at $C000-$C00F, which reading reads
  the keyboard) where they're written, e.g. 'sta SET80VID', and the Disk
  II's, indexed by the slot times 16, where they're used, e.g. 'lda
  Q6L,x' (comment_soft_switches()); on the IIc, its own switches replace
  those it lacks or differs in (the mouse's and the vertical blank's
  interrupts, IOUDIS etc.: see switch_tables());
- names Applesoft's routines (STROUT, CHRGET, the hi-res routines etc.),
  whose calls are commented in the same way (e.g. STROUT's string is
  marked, 'Print 4660' for LINPRT, 'Plot a hi-res point at (140, 96)' for
  HPLOT0), and its zero page, and traces the handlers code sets the USR
  function's and the & command's JMPs to;
- follows ProDOS 8's MLI calls (a JSR to $BF00, then the call number and
  the address of its parameter list): tracing carries on after them, the
  number is named (e.g. 'MLI_OPEN'), the call commented ('ProDOS: open a
  file'), and the parameter list labelled and marked, with its pathname,
  buffers and handler (mli_hook()); and names ProDOS's global page
  ($BF00-$BFFF: MLI, DEVNUM, DATE, MACHID etc.);
- names DOS 3.3's entry points in page 3 (dos_rwts, dos_file_manager,
  dos_get_iob etc.), whose calls are commented: for RWTS, the IOB whose
  address Y and A are loaded with is labelled ('rwts_iob') and marked, with
  its fields, its device characteristics table and its sector buffer
  (_rwts_hook()); and names DOS's memory (IOB, IBSLOT, IBTRK and the other
  fields of DOS's own IOB, DCT, and the length and address of the file last
  loaded etc.). Tracing stops after a JSR to DOS's warm or cold start.
  ProDOS's and DOS's names and hooks aren't used where the program is
  loaded, since it can't then be using them there;
- makes the Apple II's high ASCII (ASCII with bit 7 set) the session's text
  encoding (see textencoding.py).

It also names the slots' ROMs at $Cn00 (e.g. 'slot_3_entry'), which
programs call as PR#n does, with comments (e.g. 'Start the 80-column
firmware (as PR#3 does)').

applesoft_program() marks an Applesoft program, listing its lines in
comments, and traces the machine code its CALLs call. slot_rom() sets up
for a card's ROM at $Cn00: its entry points, and those its ID bytes give (a
ProDOS block device's driver and SmartPort dispatcher, a Pascal 1.1 card's
routines, the mouse's). smartport_calls() decodes the SmartPort calls a
program makes through a JMP of its own.

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
import classification
import cpu6502
import cpu6510
import disassembly
import mainformatter
import memorymanager
import movemanager
import session
import textencoding
import utils
from align import Align
from format import Format
from memorymanager import BinaryAddr, BinaryLocation, RuntimeAddr
from maker import make_lo
import msbasic
from snippets6502 import register_snippet
from snippethelper import vector_pattern, vector_handler, vector_handler_name, comment_vector, half_set_vector_text
from acornhelpers import character_streams, register_print_snippets, xy_addr

# The data tables, which control files can use as e.g.
# apple.apple2_monitor_routines
from appletables import *

# The models apple2() knows, and the styles of names
MODELS = ("ii+", "iie", "iie-enhanced", "iic")
NAMES = ("apple", "descriptive")

# The models with the IIe's memory, switches and firmware (the IIe's
# family), and those with a 65C02
IIE_FAMILY = ("iie", "iie-enhanced", "iic")
CMOS_MODELS = ("iie-enhanced", "iic")

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

def _model():
    """The session's model (see MODELS), or None before apple2()."""
    return session.current().extras.get("apple.model")

def switch_tables(model):
    """The soft switches for the model (see MODELS), from the tables in
    appletables.py: (names, inputs, actions, write switches), where names
    is {address: (Apple's name, descriptive name)} for any access (and the
    language card's), inputs and actions are as apple2_inputs and
    apple2_switch_actions, and write switches as apple2e_write_switches.
    The IIe's family has the IIe's, and the IIc its own in place of those it
    lacks or differs in."""
    names = dict(apple2_soft_switches)
    names.update(apple2_language_card)
    inputs = dict(apple2_inputs)
    actions = dict(apple2_switch_actions)
    writes = {}
    if model in IIE_FAMILY:
        names.update(apple2e_soft_switches)
        inputs.update(apple2e_inputs)
        writes.update(apple2e_write_switches)
    if model in CMOS_MODELS:
        apple_name, descriptive_name, _ = writes[0xc00f]
        writes[0xc00f] = (apple_name, descriptive_name, APPLE2E_ENHANCED_ALTCHAR)
    if model == "iic":
        for table in (names, inputs, actions, writes):
            for addr in apple2c_missing_switches:
                table.pop(addr, None)
        names.update(apple2c_soft_switches)
        inputs.update(apple2c_inputs)
        actions.update(apple2c_switch_actions)
        writes.update(apple2c_write_switches)
    return names, inputs, actions, writes

def _name(apple_name, descriptive_name):
    """The name in the session's style (Apple's, as official_name() gives
    it, or the descriptive one). Where Apple has no name (apple_name is
    None), it's the descriptive one in both styles."""
    return official_name(apple_name) if _names() == "apple" and apple_name is not None else descriptive_name


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

def _hires_colour_text(x):
    """SETHCOL's comment, e.g. 'Set the hi-res colour to 3 (white)'."""
    if x < 8:
        return "Set the hi-res colour to {0} ({1})".format(x, apple2_hires_colours[x])
    return None

def _xy_hook(describe, regs):
    """A hook like _call_hook()'s, for values in several registers: the text
    is describe(values), with the values of the registers in 'regs' (e.g.
    'xya'), if they're all known."""
    def hook(runtime_addr, state, subroutine):
        values = [_known(state, reg) for reg in regs]
        text = describe(*values) if None not in values else None
        if text is not None:
            subroutine = copy.copy(subroutine)
            subroutine.title = text
            subroutine.on_entry = {reg: description for reg, description in subroutine.on_entry.items() if reg not in regs}
        session.current().cpu.default_subroutine_hook(runtime_addr, state, subroutine)
    return hook

def _strout_hook(runtime_addr, state, subroutine):
    """STROUT's hook: where A and Y are loaded, write them as the low and
    high bytes of the string's label (see acornhelpers.xy_addr()), and mark
    the string as a zero-terminated one, if it's loaded and isn't classified
    yet: in high ASCII, or in ASCII if its first byte has bit 7 clear
    (STROUT prints either). Then comment the call as the default hook does
    (without the comments on A and Y, if they're the string's label)."""
    string_addr = None
    if subroutine.runtime_addr != runtime_addr:
        string_addr = xy_addr(state.pessimistic['a'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    if string_addr is not None:
        binary_addr, _ = movemanager.r2b(string_addr)
        if (binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr)
                and classification.get_classification(binary_addr) is None):
            stringz(string_addr, encoding="apple" if memory_binary[binary_addr] >= 0x80 else "ascii")
        # (The loads of A and Y are the string's label, so they need no
        # comments)
        subroutine = copy.copy(subroutine)
        subroutine.on_entry = {}
    session.current().cpu.default_subroutine_hook(runtime_addr, state, subroutine)

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
    # Applesoft's
    0xdb3a: _strout_hook,                                                                       # STROUT
    0xed24: _xy_hook(lambda a, x: "Print {0}".format(a * 256 + x), "ax"),                       # LINPRT
    0xf411: _xy_hook(lambda x, y, a: "Move the hi-res position to ({0}, {1})".format(y * 256 + x, a), "xya"),  # HPOSN
    0xf457: _xy_hook(lambda x, y, a: "Plot a hi-res point at ({0}, {1})".format(y * 256 + x, a), "xya"),      # HPLOT0
    0xf53a: _xy_hook(lambda a, x, y: "Draw a hi-res line to ({0}, {1})".format(x * 256 + a, y), "axy"),       # HGLIN
    0xf6f0: _call_hook(_hires_colour_text, 'x'),                                                # SETHCOL
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
# The soft switches: what code does with them

# The 6502's instructions with an absolute operand, by what they do to the
# address: read it, write it, or both (read-modify-write); and those indexed
# by X or Y
_ABSOLUTE_READS = {0xad, 0xae, 0xac, 0x2c, 0xcd, 0xec, 0xcc, 0x6d, 0xed, 0x2d, 0x0d, 0x4d}
_ABSOLUTE_WRITES = {0x8d, 0x8e, 0x8c}
_ABSOLUTE_RMW = {0xee, 0xce, 0x0e, 0x4e, 0x2e, 0x6e}
_INDEXED = {0xbd, 0xbc, 0xdd, 0x7d, 0xfd, 0x3d, 0x1d, 0x5d, 0x9d, 0xfe, 0xde, 0x1e, 0x5e, 0x3e, 0x7e,
            0xb9, 0xbe, 0xd9, 0x79, 0xf9, 0x39, 0x19, 0x59, 0x99}

# The 65C02's: STZ, TSB and TRB, and BIT and STZ indexed by X (which are
# other instructions on a 6502)
_CMOS_ABSOLUTE_WRITES = {0x9c}
_CMOS_ABSOLUTE_RMW = {0x0c, 0x1c}
_CMOS_INDEXED = {0x3c, 0x9e}

# The branches on bit 7 (N), which wait loops use: BPL and BMI
_BPL, _BMI = 0x10, 0x30

def comment_soft_switches():
    """Comment what the code does with the soft switches, the language card
    and the Disk II (see the tables in appletables.py), and name the IIe's
    write-only switches and the Disk II's, where they're used:
    - an access to a switch that acts when it's read or written, e.g. 'Show
      graphics' for TXTCLR, 'Click the speaker' for SPKR, or 'Language card:
      read and write RAM bank 2 (two reads in a row enable writing)';
    - a read of an input, e.g. 'Test button 0 (bit 7 set if it's pressed)',
      or 'Wait for a key' for a loop reading KBD until bit 7 is set (and on
      the IIe and enhanced IIe, 'Wait for the vertical blank' or 'Wait for
      the vertical blank to end' for RDVBLBAR, and on the IIc, 'Wait for the
      vertical blank interrupt' for VBLINT);
    - in the IIe's family, a write to $C000-$C00F (which reading reads the
      keyboard), e.g. 'Show 80 columns', with the address named for that
      write (e.g. 'sta SET80VID'; see apple2e_write_switches), and on the
      IIc, to IOUDIS (see apple2c_write_switches);
    - an access to $C080-$C08F indexed by X or Y, which is the slot whose
      number times 16 is in the register (usually a Disk II), e.g. 'lda
      Q6L,x ; Disk II: Q6 low (read the data latch)', named for that
      instruction (see apple2_disk2_switches); but in the ROM of a card
      that isn't a Disk II (see slot_rom()), with the card's names, e.g.
      'lda card_io_14,x'.
    The names for one instruction are local labels (see
    disassembly.add_local_label()). The switches are the model's (see
    switch_tables()), and for a 65C02, its STZ, TSB and TRB count too. (Run
    once the code has been traced, as an analysis hook.)"""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    moves = session.current().moves.move_id_for_binary_addr
    model = _model()
    _, inputs, actions, write_switches = switch_tables(model)
    card_roms = session.current().extras.get("apple.card_roms", [])
    reads, writes, rmw, indexed = _ABSOLUTE_READS, _ABSOLUTE_WRITES, _ABSOLUTE_RMW, _INDEXED
    if config.get_cmos():
        writes, rmw, indexed = writes | _CMOS_ABSOLUTE_WRITES, rmw | _CMOS_ABSOLUTE_RMW, indexed | _CMOS_INDEXED

    def comment(binary_addr, text):
        """Comment the instruction at binary_addr, in the move it's in."""
        disassembly.comment_binary(BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text,
                                   align=Align.INLINE, auto_generated=True)

    def name(binary_addr, addr, apple_name, descriptive_name, heading=None):
        """Name addr as used by the instruction at binary_addr (only there)."""
        disassembly.add_local_label(RuntimeAddr(addr), _name(apple_name, descriptive_name), binary_addr, binary_addr + 3, heading=heading)

    def branches_back(run, k, branch):
        """Whether the instruction after run[k] is the branch 'branch' (an
        opcode) back to run[k]."""
        if k + 1 >= len(run) or memory_binary[run[k + 1]] != branch:
            return False
        offset = memory_binary[run[k + 1] + 1]
        target = run[k + 1] + 2 + (offset - 256 if offset >= 128 else offset)
        return target == run[k]

    for run in cpu.straight_runs():
        for k, binary_addr in enumerate(run):
            opcode = memory_binary[binary_addr]
            if opcode not in reads and opcode not in writes and opcode not in rmw and opcode not in indexed:
                continue
            addr = memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]
            if opcode in indexed:
                # The Disk II (or another card) in the slot whose number
                # times 16 is in X or Y
                if 0xc080 <= addr <= 0xc08f:
                    if any(start <= binary_addr < end for start, end in card_roms):
                        # (In a card's ROM, not a Disk II's: see slot_rom())
                        name(binary_addr, addr, None, "card_io_{0}".format(addr & 0x0f), SLOT_CARD_IO_HEADING)
                    else:
                        apple_name, descriptive_name, text = apple2_disk2_switches[addr & 0x0f]
                        name(binary_addr, addr, apple_name, descriptive_name, APPLE2_DISK2_HEADING)
                        comment(binary_addr, text)
                continue
            if 0xc080 <= addr <= 0xc08f:
                comment(binary_addr, apple2_language_card_action(addr))
            elif opcode in writes and addr in write_switches:
                apple_name, descriptive_name, text = write_switches[addr]
                name(binary_addr, addr, apple_name, descriptive_name)
                comment(binary_addr, text)
            elif addr in actions:
                comment(binary_addr, actions[addr])
            elif opcode in reads and addr in inputs:
                if addr == 0xc000 and branches_back(run, k, _BPL):
                    text = "Wait for a key"
                elif model in ("iie", "iie-enhanced") and addr == 0xc019 and branches_back(run, k, _BMI):
                    text = "Wait for the vertical blank"
                elif model in ("iie", "iie-enhanced") and addr == 0xc019 and branches_back(run, k, _BPL):
                    text = "Wait for the vertical blank to end"
                elif model == "iic" and addr == 0xc019 and branches_back(run, k, _BPL):
                    text = "Wait for the vertical blank interrupt"
                else:
                    text = "Test " + inputs[addr]
                comment(binary_addr, text)


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
# ProDOS 8's MLI calls

def _loaded_and_unclassified(runtime_addr, length):
    """Whether there's data loaded for the length bytes at the runtime
    address, none of it classified yet."""
    for i in range(length):
        if runtime_addr + i > 0xffff:
            return False
        binary_addr, _ = movemanager.r2b(RuntimeAddr(runtime_addr + i))
        if (binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr)
                or classification.get_classification(binary_addr) is not None):
            return False
    return True

def _loaded(runtime_addr):
    """Whether data is loaded at the runtime address."""
    binary_addr, _ = movemanager.r2b(RuntimeAddr(runtime_addr))
    return binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr)

def _u8(runtime_addr):
    """The byte at a runtime address (which must be loaded)."""
    binary_addr, _ = movemanager.r2b(RuntimeAddr(runtime_addr))
    return memory_binary[binary_addr]

def _data_name(runtime_addr, name):
    """The name of the address: its first explicit name, if it has one, or
    else the given name, which it's labelled with (then name_2 etc. for the
    next address given the same name, counted for the session)."""
    existing = vector_handler_name(runtime_addr)
    if existing is not None:
        return existing
    counts = session.current().extras.setdefault("apple.data_names", {})
    counts[name] = counts.get(name, 0) + 1
    if counts[name] > 1:
        name = "{0}_{1}".format(name, counts[name])
    label(runtime_addr, name)
    return name

def mli_call_name(apple_name):
    """The name of an MLI call's number, e.g. 'MLI_OPEN' (Apple's names, in
    capitals unless config.set_upper_case_os_calls(False)) or 'mli_open'."""
    return official_name("MLI_" + apple_name) if _names() == "apple" else "mli_" + apple_name.lower()

# The labels given to the buffers that parameter lists point to, by the
# parameter's kind (see prodos_mli_calls and smartport_calls_table)
_BUFFER_NAMES = {"buffer": "data_buffer", "io_buffer": "io_buffer", "status_list": "status_list", "control_list": "control_list"}

def _parameter_list(params, fields, call_name):
    """Mark the parameter list of an MLI call (or a SmartPort call) at params
    (see prodos_mli_calls and smartport_calls_table): the parameter count,
    then each parameter, commented with what it is. The address of a
    pathname, buffer or handler is written as its label (e.g. 'pathname',
    'data_buffer', 'io_buffer', 'status_list' or 'interrupt_handler', unless
    it has a name; see _BUFFER_NAMES), a reference number is
    labelled from the call (e.g. 'open_ref', which code often copies to
    the next calls' lists), a pathname is marked as a
    length-prefixed string (in ASCII, or high ASCII if its first character
    has bit 7 set), and a handler is traced. Only if the list is loaded and
    nothing in it is classified yet. If its count isn't the call's, only
    the count is marked."""
    sizes = {"byte": 1, "word": 2, "3": 3, "pathname": 2, "code": 2}
    sizes.update({kind: 2 for kind in _BUFFER_NAMES})
    if not _loaded_and_unclassified(params, 1 + sum(sizes[kind] for _, kind in fields)):
        return
    byte(params)
    if _u8(params) != len(fields):
        auto_comment(params, "Parameter count (but the call's is {0})".format(len(fields)), align=Align.INLINE)
        return
    auto_comment(params, "Parameter count", align=Align.INLINE)
    addr = params + 1
    for description, kind in fields:
        if kind == "byte":
            byte(addr)
            if description.startswith("Reference number"):
                _data_name(addr, call_name + "_ref")
        elif kind == "3":
            byte(addr, 3)
        else:
            word(addr)
            pointer = _u8(addr) + 256 * _u8(addr + 1)
            if kind != "word" and pointer != 0:
                if kind == "pathname":
                    name = _data_name(pointer, "pathname")
                    if _loaded_and_unclassified(pointer, 1) and _loaded_and_unclassified(pointer, 1 + _u8(pointer)):
                        first = _u8(pointer + 1) if _u8(pointer) > 0 else 0
                        stringn(pointer, encoding="apple" if first >= 0x80 else "ascii")
                elif kind == "code":
                    if _loaded(pointer):
                        entry(pointer)
                    name = _data_name(pointer, "interrupt_handler")
                else:
                    name = _data_name(pointer, _BUFFER_NAMES[kind])
                expr(addr, name)
        auto_comment(addr, description, align=Align.INLINE)
        addr += sizes[kind]

def mli_hook(target, caller):
    """The tracing hook (see Cpu.subroutine_hooks) for a call to ProDOS's
    MLI ($BF00): the JSR is followed by the call number and the address of
    its parameter list, so tracing carries on after them. The call number
    is written as its name (e.g. 'MLI_OPEN'), the address as the parameter
    list's label (e.g. 'open_params', unless it has a name), and the
    parameter list is marked (see _parameter_list()); the call is
    commented, e.g. 'ProDOS: open a file'. If the bytes after the JSR
    aren't loaded, or are classified already, they're left alone. Tracing
    stops after QUIT, which doesn't return."""
    number_addr = caller + 3
    if not _loaded_and_unclassified(number_addr, 3):
        return caller + 3
    number = _u8(number_addr)
    params = _u8(number_addr + 1) + 256 * _u8(number_addr + 2)
    byte(number_addr)
    word(number_addr + 1)
    call = prodos_mli_calls.get(number)
    if call is None:
        auto_comment(caller, "ProDOS: call {0}".format(_hex2(number)), align=Align.INLINE)
        if params != 0:
            _label_at(number_addr + 1, params)
        return caller + 6
    apple_name, title, fields = call
    name = mli_call_name(apple_name)
    constant(number, name, format=Format.HEX)
    expr(number_addr, name)
    auto_comment(caller, "ProDOS: " + title, align=Align.INLINE)
    # (GET_TIME has no parameters, so its address is usually 0)
    if fields and params != 0:
        expr(number_addr + 1, _data_name(params, apple_name.lower() + "_params"))
        _parameter_list(params, fields, apple_name.lower())
    # (QUIT doesn't return)
    return None if number == PRODOS_MLI_QUIT else caller + 6


# ************************************************************************************************
# DOS 3.3: RWTS and the file manager

def _object_name(runtime_addr, name):
    """Label the runtime address with the name (or name_2 etc.: see
    _data_name()), unless it has an explicit name already, or an optional
    label of its own (e.g. DOS's IOB's, 'IOB'), which is then the one
    used."""
    optional = session.current().disassembly.optional_labels.get(runtime_addr)
    if optional is not None and optional.base_address is None and vector_handler_name(runtime_addr) is None:
        return
    _data_name(runtime_addr, name)

def _label_at(runtime_addr, target):
    """Write the word at runtime_addr as the label of the target address."""
    auto_expr(runtime_addr, _label_ref(target, runtime_addr))

def _rwts_dct(dct):
    """Mark a device characteristics table (see dos33_dct_fields), if it's
    loaded and nothing in it is classified yet."""
    if not _loaded_and_unclassified(dct, 4):
        return
    addr = dct
    for description, kind in dos33_dct_fields:
        if kind == "byte":
            byte(addr)
        else:
            word(addr)
        auto_comment(addr, description, align=Align.INLINE)
        addr += 1 if kind == "byte" else 2

def _rwts_iob(iob):
    """Mark a program's IOB for RWTS (see dos33_iob_fields), if it's loaded
    and nothing in it is classified yet: each field is a byte or a word,
    commented with what it is, and gets an optional label, named from the
    IOB's (e.g. 'rwts_iob_track'), used where the code refers to it (unless
    it has an optional label already). The
    address of the device characteristics table is written as its label
    ('rwts_dct', unless it has a name, such as DOS's own 'DCT'), and the
    table is marked (see _rwts_dct()); the address of the sector buffer is
    written as its label ('sector_buffer', unless it has a name). (An
    address of 0 is left alone, since the code must set it.)"""
    if not _loaded_and_unclassified(iob, DOS33_IOB_LENGTH):
        return
    iob_name = vector_handler_name(iob)
    optional_labels = session.current().disassembly.optional_labels
    for offset, suffix, description, kind in dos33_iob_fields:
        addr = iob + offset
        # (Not where there's an optional label already, e.g. 'IN+5' for an
        # IOB in the input buffer)
        if suffix is not None and iob_name is not None and addr not in optional_labels:
            optional_label(addr, "{0}_{1}".format(iob_name, suffix))
        if kind == "byte":
            byte(addr)
        else:
            word(addr)
            pointer = _u8(addr) + 256 * _u8(addr + 1)
            if pointer != 0:
                _object_name(pointer, "rwts_dct" if kind == "dct" else "sector_buffer")
                _label_at(addr, pointer)
                if kind == "dct":
                    _rwts_dct(pointer)
        auto_comment(addr, description, align=Align.INLINE)

def _rwts_hook(runtime_addr, state, subroutine):
    """RWTS's hook (for dos_rwts, dos_rwts_entry and RWTS): where Y and A are
    loaded with the low and high bytes of the IOB's address, write them as
    its label's (e.g. 'ldy #<rwts_iob', with 'rwts_iob', then 'rwts_iob_2'
    etc., unless it has a name, such as DOS's own IOB's, 'IOB'), and mark the
    IOB (see _rwts_iob()). Then comment the call as the default hook does
    (without the comments on Y and A, if they're the IOB's label)."""
    if subroutine.runtime_addr != runtime_addr:
        lo = state.pessimistic['y'].get_previous_load_imm_operand()
        hi = state.pessimistic['a'].get_previous_load_imm_operand()
        if lo is not None and hi is not None:
            iob = memory_binary[lo] + 256 * memory_binary[hi]
            _object_name(iob, "rwts_iob")
            xy_addr(lo, hi)
            _rwts_iob(iob)
            subroutine = copy.copy(subroutine)
            subroutine.on_entry = {}
    session.current().cpu.default_subroutine_hook(runtime_addr, state, subroutine)

def _file_manager_text(x):
    """The comment on a call to the file manager, for X (its file creation
    flag)."""
    if x == 0:
        return "Call DOS's file manager (creating the file if it isn't found)"
    return "Call DOS's file manager (not creating the file if it isn't found)"

# The hooks of DOS's routines that have their own (as _HOOKS)
_DOS33_HOOKS = {
    0x03d6: _call_hook(_file_manager_text, 'x'),    # dos_file_manager
    0x03d9: _rwts_hook,                             # dos_rwts
    0xb7b5: _rwts_hook,                             # dos_rwts_entry
    0xbd00: _rwts_hook,                             # RWTS
}

def _slot_entry_title(slot, model):
    """The comment on a call to slot n's ROM at $Cn00."""
    if slot == 3 and model in IIE_FAMILY:
        return "Start the 80-column firmware (as PR#3 does)"
    if slot == 6:
        return "Start slot 6's firmware (as PR#6 does: for a disk, boot it)"
    return "Start slot {0}'s firmware (as PR#{0} does)".format(slot)

def _no_return_hook(target, caller):
    """The tracing hook (see Cpu.subroutine_hooks) for DOS's warm and cold
    starts, which don't return: tracing stops after a JSR to them."""
    return None


# ************************************************************************************************
# SmartPort's calls

def smartport_call_name(name):
    """The name of a SmartPort call's number, e.g. 'SP_READBLOCK' (in
    capitals unless config.set_upper_case_os_calls(False)) or
    'smartport_readblock'."""
    return official_name("SP_" + name) if _names() == "apple" else "smartport_" + name.lower()

def smartport_hook(target, caller):
    """The tracing hook (see Cpu.subroutine_hooks) for a call to SmartPort's
    dispatcher (see smartport_calls()): as mli_hook() for the MLI, the JSR
    is followed by the call number and the address of its parameter list,
    so tracing carries on after them; the number is written as its name
    (e.g. 'SP_READBLOCK'), the address as the parameter list's label (e.g.
    'sp_readblock_params', unless it has a name), and the parameter list is
    marked (see _parameter_list() and smartport_calls_table); the call is
    commented, e.g. 'SmartPort: read a block'. An extended call ($40 and
    up) isn't decoded, and tracing stops after it."""
    number_addr = caller + 3
    if not _loaded_and_unclassified(number_addr, 1):
        return caller + 3
    number = _u8(number_addr)
    if number >= SMARTPORT_EXTENDED:
        byte(number_addr)
        auto_comment(caller, "SmartPort: extended call {0} (not decoded, so tracing stops)".format(_hex2(number)), align=Align.INLINE)
        return None
    if not _loaded_and_unclassified(number_addr, 3):
        return caller + 3
    params = _u8(number_addr + 1) + 256 * _u8(number_addr + 2)
    byte(number_addr)
    word(number_addr + 1)
    call = smartport_calls_table.get(number)
    if call is None:
        auto_comment(caller, "SmartPort: call {0}".format(_hex2(number)), align=Align.INLINE)
        if params != 0:
            _label_at(number_addr + 1, params)
        return caller + 6
    name, title, fields = call
    constant(number, smartport_call_name(name), format=Format.HEX)
    expr(number_addr, smartport_call_name(name))
    auto_comment(caller, "SmartPort: " + title, align=Align.INLINE)
    if params != 0:
        call_name = "sp_" + name.lower()
        expr(number_addr + 1, _data_name(params, call_name + "_params"))
        _parameter_list(params, fields, call_name)
    return caller + 6

def smartport_calls(runtime_addr):
    """Say that a JSR to runtime_addr is a call to SmartPort's dispatcher,
    followed by the call number and the address of its parameter list (see
    smartport_hook()). A program finds the dispatcher in a slot's ROM as it
    runs, so it usually calls it through a JMP of its own whose address it
    sets: give that JMP's address. It's labelled 'smartport' unless it has a
    name. Call it after apple.apple2()."""
    if _model() is None:
        utils.die("apple.smartport_calls(): call apple.apple2() first")
    runtime_addr = RuntimeAddr(runtime_addr)
    session.current().cpu.subroutine_hooks[runtime_addr] = smartport_hook
    _data_name(runtime_addr, "smartport")


# ************************************************************************************************
# Slot firmware: a card's ROM at $Cn00

def _hex4(n):
    """A 4 digit hex number for a comment, e.g. $c701."""
    return config.get_assembler().hex4_for_comment(n)

def _label_ref(target, runtime_addr):
    """The label of the target address, as used at runtime_addr."""
    binary_addr, _ = movemanager.r2b(RuntimeAddr(runtime_addr))
    return get_label(target, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)

def _status_text(status):
    """The comment on a ProDOS block device's status byte ($CnFE), e.g.
    'Status: 1 volume; writes, reads, gives its status'."""
    volumes = (status >> 4) & 3
    features = [slot_status_bits[bit] for bit in sorted(slot_status_bits, reverse=True) if status & (1 << bit)]
    text = "Status: {0} volume{1}".format(volumes, "" if volumes == 1 else "s")
    return text + ("; " + ", ".join(features) if features else "")

def _slot_offset_table(base, routines):
    """Mark a table of routines' offsets in a card's ROM (the low bytes of
    their addresses, in the page at base): each is a byte written as its
    routine's label's low byte (and commented with the routine's name, e.g.
    'Offset of POSMOUSE', since routines can share one), the routine traced
    and labelled (e.g. 'pascal_init', unless it has a name; see
    slot_pascal_routines), with a comment before it saying what it is. Only
    for offsets that are loaded and not yet classified."""
    for offset, apple_name, descriptive_name, text in routines:
        if not _loaded_and_unclassified(base + offset, 1):
            continue
        byte(base + offset)
        target = base + _u8(base + offset)
        name = _data_name(target, _name(apple_name, descriptive_name))
        if _loaded(target):
            entry(target)
            auto_comment(target, text)
        auto_expr(base + offset, make_lo(_label_ref(target, base + offset)))
        auto_comment(base + offset, "Offset of " + _name(apple_name, descriptive_name), align=Align.INLINE)

def _slot_byte(addr, text):
    """Mark a byte of a card's ROM, with a comment, if it's loaded and not
    yet classified."""
    if _loaded_and_unclassified(addr, 1):
        byte(addr)
        auto_comment(addr, text, align=Align.INLINE)

def slot_rom(slot):
    """Set up for a peripheral card's ROM, loaded at $Cn00 for slot n (1 to
    7), after apple.apple2() (see docs/machines/apple2.md):
    - $Cn00, where PR#n, IN#n and booting from slot n start, is traced and
      labelled (e.g. 'slot_7_entry', unless it has a name);
    - a ProDOS block device ($20, $00 and $03 at $Cn01, $Cn03 and $Cn05):
      its ID bytes are described (and $Cn07: $3C, which the Autostart ROM
      boots as a Disk II, or $00 for SmartPort), and from $CnFF, the low
      byte of its driver's address (if it isn't $00 or $FF, a Disk II), the
      driver is traced and labelled ('prodos_driver'), the number of blocks
      ($CnFC) and the status byte ($CnFE) are marked, and ProDOS's
      parameters in zero page get their names in the ROM ('driver_command'
      etc.: see slot_driver_zero_page); SmartPort's dispatcher, 3 bytes on,
      is traced and labelled ('smartport'), and calls to it decoded (see
      smartport_hook());
    - a Pascal 1.1 card ($38, $18 and $01 at $Cn05, $Cn07 and $Cn0B): BASIC's
      input and output entry points at $Cn05 and $Cn07 are traced
      ('basic_input', 'basic_output'), the device signature at $Cn0C is
      described, and the offsets of the INIT, READ, WRITE and STATUS
      routines at $Cn0D-$Cn10 are marked, and the routines traced and
      labelled ('pascal_init' etc.); for the mouse (signature $20), its
      routines' offsets at $Cn12-$Cn19 too ('SETMOUSE' etc.);
    - MSLOT ($07F8), where a card notes that it's using the expansion ROM,
      is named.
    Names given more than once (for several slots) get _2 etc. It stops
    with an error if apple.apple2() hasn't been called, the slot isn't 1 to
    7, or nothing is loaded at $Cn00."""
    if _model() is None:
        utils.die("apple.slot_rom(): call apple.apple2() first")
    if not isinstance(slot, int) or isinstance(slot, bool) or not 1 <= slot <= 7:
        utils.die("apple.slot_rom(): the slot must be 1 to 7, not {0!r}".format(slot))
    base = 0xc000 + 0x100 * slot
    if not _loaded(base):
        utils.die("apple.slot_rom({0}): nothing is loaded at {1} (load the card's ROM there)".format(slot, config.get_assembler().hex4(base)))

    def rom(offset):
        """The byte at $Cn00 + offset, or None if it isn't loaded."""
        return _u8(base + offset) if _loaded(base + offset) else None

    entry(base)
    _data_name(base, "slot_{0}_entry".format(slot))
    auto_comment(base, "Slot {0}'s ROM: PR#{0}, IN#{0} and booting from slot {0} start here".format(slot))
    recognised = False

    # A ProDOS block device (and SmartPort, or a Disk II)
    if all(rom(offset) == value for offset, value in SLOT_BLOCK_DEVICE_ID.items()):
        recognised = True
        text = "ID bytes $20, $00 and $03 at {0}, {1} and {2}: a ProDOS block device".format(_hex4(base + 1), _hex4(base + 3), _hex4(base + 5))
        if rom(7) == SLOT_DISK2_ID:
            text += ", which the Autostart ROM boots ($3C at {0}, as a Disk II's)".format(_hex4(base + 7))
        elif rom(7) == SLOT_SMARTPORT_ID:
            text += ", with SmartPort ($00 at {0})".format(_hex4(base + 7))
        auto_comment(base, text)
        low = rom(0xff)
        if low == 0x00:
            _slot_byte(base + 0xff, "$00: a Disk II with 16-sector ROMs, which ProDOS drives itself")
        elif low == 0xff:
            _slot_byte(base + 0xff, "$FF: a Disk II with 13-sector ROMs, which ProDOS doesn't use")
        elif low is not None:
            driver = base + low
            entry(driver)
            _data_name(driver, "prodos_driver")
            auto_comment(driver, "ProDOS's driver for the device (with its parameters at $42-$47)")
            if _loaded_and_unclassified(base + 0xfc, 2):
                word(base + 0xfc)
                auto_comment(base + 0xfc, "Number of blocks (0: read it with STATUS)", align=Align.INLINE)
            if rom(0xfe) is not None:
                _slot_byte(base + 0xfe, _status_text(rom(0xfe)))
            if _loaded_and_unclassified(base + 0xff, 1):
                byte(base + 0xff)
                auto_expr(base + 0xff, make_lo(_label_ref(driver, base + 0xff)))
                auto_comment(base + 0xff, "The low byte of the driver's address", align=Align.INLINE)
            # ProDOS's parameters in zero page, named in the ROM (and the
            # expansion ROM, if it's loaded)
            ranges = [(base, base + 0x100)]
            if _loaded(0xc800):
                ranges.append((0xc800, 0xd000))
            for addr, name in slot_driver_zero_page.items():
                for start, end in ranges:
                    disassembly.add_local_label(RuntimeAddr(addr), name, BinaryAddr(start), BinaryAddr(end), heading=SLOT_DRIVER_HEADING)
            if rom(7) == SLOT_SMARTPORT_ID and _loaded(driver + 3):
                dispatcher = driver + 3
                entry(dispatcher)
                _data_name(dispatcher, "smartport")
                auto_comment(dispatcher, "SmartPort's dispatcher: a JSR to it is followed by the call number and the address of its parameter list")
                session.current().cpu.subroutine_hooks[RuntimeAddr(dispatcher)] = smartport_hook

    # A Pascal 1.1 card (and the mouse)
    if all(rom(offset) == value for offset, value in SLOT_PASCAL_ID.items()):
        recognised = True
        auto_comment(base, "ID bytes $38, $18 and $01 at {0}, {1} and {2}: the Pascal 1.1 firmware protocol".format(_hex4(base + 5), _hex4(base + 7), _hex4(base + 0x0b)))
        for offset, name, text in ((5, "basic_input", "BASIC's input entry point (whose SEC is the ID byte $38)"),
                                   (7, "basic_output", "BASIC's output entry point (whose CLC is the ID byte $18)")):
            entry(base + offset)
            _data_name(base + offset, name)
            auto_comment(base + offset, text)
        _slot_byte(base + 0x0b, "Pascal 1.1's generic signature")
        signature = rom(0x0c)
        if signature is not None:
            device_class = slot_pascal_classes.get(signature >> 4)
            text = "Device signature: class {0}{1}, ID {2}".format(signature >> 4, " ({0})".format(device_class) if device_class else "", signature & 0x0f)
            _slot_byte(base + 0x0c, text)
        routines = list(slot_pascal_routines)
        if signature == SLOT_MOUSE_SIGNATURE:
            routines += slot_mouse_routines
        _slot_offset_table(base, routines)

    if not recognised:
        auto_comment(base, "(No ID bytes of a ProDOS block device or a Pascal 1.1 card)")

    # The card's I/O: $C080 + 16n to $C08F + 16n, named for the slot (e.g.
    # 'slot_7_io+7') where an address there has no name already; and
    # unless it's a Disk II's ROM, the accesses in the ROM indexed by the
    # slot times 16 (e.g. 'lda $c08e,x') get the card's names, not the
    # Disk II's (see comment_soft_switches())
    io = 0xc080 + 0x10 * slot
    optional_labels = session.current().disassembly.optional_labels
    io_name = "slot_{0}_io".format(slot)
    if io not in optional_labels:
        optional_label(io, io_name, definable_inline=False)
        for i in range(1, 16):
            if io + i not in optional_labels:
                optional_label(io + i, "{0}+{1}".format(io_name, i), io, definable_inline=False)
    disk2 = all(rom(offset) == value for offset, value in SLOT_BLOCK_DEVICE_ID.items()) and rom(0xff) in (0x00, 0xff)
    if not disk2:
        card_roms = session.current().extras.setdefault("apple.card_roms", [])
        card_roms.append((base, base + 0x100))
        if _loaded(0xc800):
            card_roms.append((0xc800, 0xd000))

    if _os_free(SLOT_MSLOT[0]):
        optional_label(SLOT_MSLOT[0], _name(SLOT_MSLOT[1], SLOT_MSLOT[2]))


# ************************************************************************************************
# Applesoft programs

def _applesoft_line_text(data):
    """A tokenised Applesoft line's text (data, its bytes) as LIST shows it,
    with a space either side of each keyword (except in quotes, or after
    REM or DATA), e.g. 'HOME : PRINT "HELLO"'. Other codes are shown as
    e.g. {$80}."""
    result = ""
    space_due = False   # (A space is due after a keyword)
    in_quotes = in_rem = False
    for c in data:
        if c == ord('"') and not in_rem:
            in_quotes = not in_quotes
        if c >= 0x80 and not in_quotes and not in_rem and c - 0x80 < len(applesoft_tokens):
            if result and not result.endswith(" "):
                result += " "
            result += applesoft_tokens[c - 0x80]
            space_due = True
            in_rem = c == APPLESOFT_TOKEN_REM
            continue
        char = chr(c) if 32 <= c < 127 else textencoding.APPLE.char(c)
        if char is None:
            char = "{%s}" % _hex2(c)
        if space_due and char != " ":
            result += " "
        space_due = False
        result += char
    return result

def _call_addresses(text):
    """The addresses that CALLs in a line call (text, its bytes): each CALL
    token's number, which can be negative (e.g. CALL -936 for $FC58)."""
    result = []
    for i, c in enumerate(text):
        if c != APPLESOFT_TOKEN_CALL:
            continue
        digits = ""
        for d in bytes(text[i + 1:]).decode("latin-1"):
            if d.isdigit() or (d == "-" and not digits):
                digits += d
            else:
                break
        if digits.lstrip("-"):
            n = int(digits)
            if -65535 <= n <= 65535:
                result.append(n % 65536)
    return result

def applesoft_program(runtime_addr=APPLESOFT_START):
    """Classify the tokenised Applesoft program at the address (by default
    $0801, where Applesoft programs start). Each line is labelled (e.g.
    'basic_line_10'), its link to the next line and its line number are
    words, and its text is bytes for the keywords and ASCII strings, listed
    in a comment, e.g. '; 10 HOME : PRINT "HELLO"'. An address a CALL calls
    in the loaded data is an entry point, named 'call_entry' (then
    'call_entry_2' etc.) unless it already has a name. Returns the address
    after the program, or None (classifying nothing) if there isn't a valid
    program there (see msbasic.basic_lines())."""
    found = msbasic.basic_lines(runtime_addr)
    if found is None:
        return None
    lines, end = found
    # Each line's label, e.g. 'basic_line_10' (or 'basic_line_10_2' for a
    # second line 10), and 'basic_end' for the two zeros at the end
    names = {}
    def line_name(number):
        """The label for the next line with this line number."""
        name = "basic_line_%d" % number
        names[name] = names.get(name, 0) + 1
        return name if names[name] == 1 else "%s_%d" % (name, names[name])
    line_names = [line_name(number) for _, _, number, _ in lines] + ["basic_end"]

    calls = []
    for i, (addr, link, number, text) in enumerate(lines):
        # The line's label and listing, its link (written as the next line's
        # label) and its line number (in decimal)
        label(addr, line_names[i])
        auto_comment(addr, "%d %s" % (number, _applesoft_line_text(text)))
        word(addr)
        expr(addr, line_names[i + 1])
        word(addr + 2)
        decimal(addr + 2)
        # The text: runs of ASCII characters as strings, the rest (keywords
        # and other codes) as bytes
        a = addr + 4
        run_start = None
        for c in text:
            if 32 <= c < 127:
                if run_start is None:
                    run_start = a
            else:
                if run_start is not None:
                    string(run_start, a - run_start, encoding="ascii")
                    run_start = None
                byte(a)
            a += 1
        if run_start is not None:
            string(run_start, a - run_start, encoding="ascii")
        byte(a)     # (the zero at the end of the line)
        calls += _call_addresses(text)

    label(end, "basic_end")
    word(end)

    # The machine code that CALLs call, if it's loaded
    count = 0
    for call_addr in calls:
        binary_addr, _ = movemanager.r2b(RuntimeAddr(call_addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            continue
        entry(call_addr)
        labels = session.current().labels.labels
        if not (call_addr in labels and labels[call_addr].explicit_names):
            count += 1
            label(call_addr, "call_entry" if count == 1 else "call_entry_%d" % count)
    return end + 2


# ************************************************************************************************
# The set-up

def _routine(addr, apple_name, descriptive_name, title, on_entry, on_exit):
    """Name a ROM routine, as an optional label, with its title, registers
    and hook (its own from _HOOKS or _DOS33_HOOKS, or the 6502's
    default)."""
    hook = _HOOKS.get(addr, _DOS33_HOOKS.get(addr))
    subroutine(addr, _name(apple_name, descriptive_name), title, None, on_entry, on_exit, hook=hook, is_entry_point=False)

def _workspace():
    """Name the workspace (see apple2_workspace, apple2_page3_vectors,
    apple2_applesoft_workspace, prodos_global_page and dos33_memory): each
    byte of a location of more than one byte is named from its start (e.g.
    'IN+1', 'output_hook+1'), except that Apple's names for the high bytes
    of some pointers are their own (e.g. 'CSWH'). A location in ProDOS's or
    DOS's memory isn't named if any of it is where the program is loaded
    (see _os_free())."""
    high_bytes = dict(apple2_workspace_high_bytes)
    high_bytes.update(apple2_applesoft_high_bytes)
    # (Each location, and whether it's ProDOS's or DOS's)
    machine = apple2_workspace + apple2_page3_vectors + apple2_applesoft_workspace
    locations = [(entry, False) for entry in machine] + [(entry, True) for entry in prodos_global_page + dos33_memory]
    for (addr, apple_name, descriptive_name, length), os_memory in locations:
        if os_memory and not all(_os_free(addr + i) for i in range(length)):
            continue
        name = _name(apple_name, descriptive_name)
        optional_label(addr, name)
        for i in range(1, length):
            if _names() == "apple" and apple_name is not None and addr + i in high_bytes:
                optional_label(addr + i, official_name(high_bytes[addr + i]))
            else:
                optional_label(addr + i, "{0}+{1}".format(name, i), addr)

def _os_free(addr):
    """Whether nothing is loaded at the address, so that ProDOS's or DOS's
    names and hooks (or a slot ROM's) can be used there: a program loaded
    where ProDOS or DOS would be doesn't use it (e.g. Penetrator, at
    $4000-$B921), so its own addresses there mustn't be given their names."""
    return not _loaded(addr)

def apple2(model="ii+", names="apple"):
    """Set up for a program for the Apple II+, IIe, enhanced IIe or IIc (see
    the module docstring): the Monitor's and Applesoft's routines, with hooks to
    comment their calls, ProDOS's MLI calls and DOS 3.3's entry points,
    the comments on what's printed, the print loops, the zero page and other
    workspace, ProDOS's and DOS's memory, the vectors and the code that sets
    them, the soft switches, the memory regions, and high ASCII as the
    session's text encoding.

    'model' is "ii+" (the default); "iie" (the unenhanced IIe, which adds
    its status switches, its memory switches and its 80-column firmware's
    AUXMOVE and XFER); "iie-enhanced" (the same, with a 65C02, and MouseText
    in its alternate character set); or "iic" (the IIc, also with a 65C02,
    whose own switches replace those of the IIe's it lacks or differs in:
    the mouse's and the vertical blank's interrupts, IOUDIS, double hi-res,
    the 40/80-column switch and the serial ports; see switch_tables()).
    'names' is "apple" for Apple's names (the default), or "descriptive".

    Call it after load(..., "6502") (or "6510" for the II+ and IIe, or
    "65C02" for the enhanced IIe and IIc, which run 6502 programs too). It
    stops with an error if the CPU isn't one the model has (the II+ and the
    unenhanced IIe have an NMOS 6502; the enhanced IIe and the IIc a 65C02,
    which doesn't run the 6502's undocumented opcodes), if the arguments
    are wrong, or if the session's machine has already been chosen. After this, config.set_upper_case_os_calls() can't
    be changed (it stops with an error), since the names have been made."""
    if model not in MODELS:
        utils.die("apple.apple2(): model must be one of {0}, not {1!r}".format(", ".join(repr(m) for m in MODELS), model))
    if names not in NAMES:
        utils.die("apple.apple2(): names must be one of {0}, not {1!r}".format(", ".join(repr(n) for n in NAMES), names))
    cpu = session.current().cpu
    if not isinstance(cpu, cpu6502.Cpu6502):
        utils.die("apple.apple2(): call load(..., \"6502\") first")
    if config.get_cmos() and model not in CMOS_MODELS:
        utils.die("apple.apple2(): the Apple II+ and IIe have a 6502, not a 65C02 (model=\"iie-enhanced\" and model=\"iic\" have a 65C02)")
    if model in CMOS_MODELS and isinstance(cpu, cpu6510.Cpu6510):
        utils.die("apple.apple2(): the enhanced IIe and the IIc have a 65C02, which doesn't run the 6502's undocumented opcodes (use load(..., \"6502\") or load(..., \"65C02\"))")
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
    for entry_ in apple2_monitor_routines + apple2_applesoft_routines:
        _routine(*entry_)
    if model in IIE_FAMILY:
        for entry_ in apple2e_firmware_routines:
            _routine(*entry_)
    for addr, apple_name, descriptive_name in apple2_rom_locations:
        optional_label(addr, _name(apple_name, descriptive_name))

    _workspace()

    # ProDOS's MLI: the call number and the parameter list's address after
    # the JSR (a tracing hook, set directly, since ProDOS isn't usually
    # loaded: see Cpu.subroutine_hooks)
    if _os_free(PRODOS_MLI):
        cpu.subroutine_hooks[RuntimeAddr(PRODOS_MLI)] = mli_hook

    # DOS 3.3's entry points, and its warm and cold starts, which don't
    # return (not where the program is loaded)
    for entry_ in dos33_routines:
        if _os_free(entry_[0]):
            _routine(*entry_)
    for addr in (DOS33_WARM_START, DOS33_COLD_START):
        if _os_free(addr):
            cpu.subroutine_hooks[RuntimeAddr(addr)] = _no_return_hook

    # The slots' ROMs, which programs call at $Cn00, as PR#n does (not where
    # the program is loaded: for a card's ROM, see slot_rom())
    for slot in range(1, 8):
        addr = 0xc000 + 0x100 * slot
        if _os_free(addr):
            subroutine(addr, "slot_{0}_entry".format(slot), _slot_entry_title(slot, model), None, None, None, is_entry_point=False)

    # The soft switches, which are always defined as 'name = value', never
    # inline
    io_range(0xc000, 0xc100)
    switches, _, _, _ = switch_tables(model)
    for addr, (apple_name, descriptive_name) in switches.items():
        optional_label(addr, _name(apple_name, descriptive_name), definable_inline=False)

    for start, end, name in apple2_memory_regions:
        memory_region(start, end, name)

    # The snippets: loops that print with COUT, and code setting a vector
    register_print_snippets(COUT)
    register_snippet(pre_trace_setting_vector, post_trace_setting_vector, vector_pattern(apple2_vectors))

    # The comments on what's printed, and on the soft switches (once the code
    # is traced)
    session.current().trace.analysis_hooks.append(comment_printing)
    session.current().trace.analysis_hooks.append(comment_soft_switches)
