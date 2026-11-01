"""
OSBYTE (&FFF4): the comments py8dis adds to a call to OSBYTE, and where.

acorn.mos_labels() makes osbyte_hook() (at the end) OSBYTE's subroutine
hook, so it's called for each call to OSBYTE once the code has been traced.
It names the OSBYTE number where A is set (with acorn.osbyte_enum), then
looks the number up in osbyte_calls, which maps each OSBYTE number to an
Osbyte saying what to say. Most OSBYTEs are described by their texts alone;
the few that need more work have a function to do it (the "Irregular
OSBYTEs" below). An OsbyteCall holds what's known at the call.

A call is commented in three places:
- where X and Y are set (e.g. "X=buffer number", or the X value named as a
  constant). This is done when the code before the call sets A to the
  OSBYTE number, if the call is reached by running straight through that
  code (the "optimistic" register state, which isn't forgotten at a
  label);
- the call itself (e.g. "Flush keyboard buffer (X=0)"), when A is known for
  certain (the "pessimistic" state, which is forgotten at a label, since
  other code could jump there), so the call is surely that OSBYTE;
- where X and Y are next used after the call, saying what OSBYTE returned in
  them (e.g. "X is the previous value of the user flag byte"), also only when
  the call is surely that OSBYTE.

Texts can use these fields, filled in at the call:
    {x}, {y}        the value of X or Y (pessimistically), or "X" or "Y" if
                    it isn't known
    {xe}, {ye}      "X=5" (say), or "X" if it isn't known
    {name}          the name of X's value (with x_names)
    {hex2[0xff]}    &ff, $ff etc, in the assembler's format
A text can also be a function, taking the OsbyteCall and returning the text.

The names and descriptions (of the buffers, events, OS variables and so on)
are in acorntables.py.
"""

from commands import auto_comment, auto_expr, binary, char, decimal, constant
from align import Align
from maker import make_eor, make_subtract
import config
import movemanager
import utils
from acorntables import *
from acornhelpers import enum_lookup
from memorymanager import memory_binary


class OsbyteCall:
    """What is known at one call to OSBYTE, and ways to comment on it.

    runtime_addr is the call's address, and 'state' the CPU state just
    before it (as a subroutine hook is given them). Attributes with _addr in
    their names (a_addr, x_addr, x_addr_optimistic etc.) are binary
    addresses, of the operand of the immediate load that set the register
    (e.g. the nn of 'ldx #nn'), or None; the rest of the addresses are
    runtime addresses, or None if there isn't one."""

    def __init__(self, runtime_addr, state):
        self.runtime_addr = runtime_addr
        optimistic, pessimistic = state.optimistic, state.pessimistic

        self.a_addr = optimistic['a'].get_previous_load_imm_operand()
        a_addr_pessimistic = pessimistic['a'].get_previous_load_imm_operand()
        # (What's known for certain is also known optimistically)
        assert (a_addr_pessimistic == self.a_addr) or (a_addr_pessimistic is None)
        # The OSBYTE number (optimistically), and whether every path to the
        # call sets A to it
        self.a = None if self.a_addr is None else memory_binary[self.a_addr]
        self.sure = a_addr_pessimistic is not None

        # Where X and Y are set to a constant on some path to the call
        # (optimistically), and on every path (pessimistically)
        self.x_addr_optimistic = optimistic['x'].get_previous_load_imm_operand()
        self.y_addr_optimistic = optimistic['y'].get_previous_load_imm_operand()
        self.x_addr = pessimistic['x'].get_previous_load_imm_operand()
        self.y_addr = pessimistic['y'].get_previous_load_imm_operand()

        # The values of X and Y, if known (pessimistically)
        self.x = None if self.x_addr is None else memory_binary[self.x_addr]
        self.y = None if self.y_addr is None else memory_binary[self.y_addr]

        # The runtime addresses of: the operand setting X and Y
        # (optimistically); the instruction that last loaded them; the
        # instruction that last changed them; and where they are next used
        # after the call
        b2r = lambda binary_addr: None if binary_addr is None else movemanager.b2r(binary_addr)
        self.x_operand = b2r(self.x_addr_optimistic)
        self.y_operand = b2r(self.y_addr_optimistic)
        self.x_load = b2r(optimistic['x'].previous_load)
        self.y_load = b2r(optimistic['y'].previous_load)
        self.x_adjust = b2r(optimistic['x'].previous_adjust)
        self.y_adjust = b2r(optimistic['y'].previous_adjust)
        self.x_next_use = b2r(state.next_use['x'])
        self.y_next_use = b2r(state.next_use['y'])

    @property
    def xy_next_use(self):
        """The first use of X or Y after the call (the lower address of the
        two), or None."""
        uses = [z for z in [self.x_next_use, self.y_next_use] if z is not None]
        return min(uses) if uses else None

    def comment(self, text, **kwargs):
        """Comment on the call itself, at the end of its line (kwargs go to
        auto_comment(), e.g. show_blank=True)."""
        auto_comment(self.runtime_addr, text, align=Align.INLINE, **kwargs)

    def exit_comment(self, runtime_addr, text):
        """Comment on where a result of the call is used: at the end of the
        line, or for a Block, before it. Does nothing if runtime_addr is
        None."""
        if isinstance(text, Block):
            auto_comment(runtime_addr, text, indent=1, show_blank=True)
        else:
            auto_comment(runtime_addr, text, align=Align.INLINE)

    def text(self, template, name=None):
        """Fill in a text's fields (see the top of this module), or call it
        if it's a function. 'name' is for {name}."""
        if callable(template):
            return template(self)
        # (str.format() gives a plain str, so a Block is made a Block again)
        result = template.format(
            x  = "X" if self.x is None else self.x,
            y  = "Y" if self.y is None else self.y,
            xe = "X" if self.x is None else "X=%d" % self.x,
            ye = "Y" if self.y is None else "Y=%d" % self.y,
            name = name,
            hex2 = _Hex2())
        return Block(result) if isinstance(template, Block) else result

def hex2(n):
    """A byte in the assembler's hex format, e.g. &ff or $ff."""
    return config.get_assembler().hex2(n)

class _Hex2:
    """So that a text can say {hex2[0xff]}: str.format() passes the index
    to __getitem__() as the string "0xff"."""
    def __getitem__(self, n):
        return hex2(int(n, 0))

class Block(str):
    """A comment of several lines, output before the line it's on (indented,
    with a blank line before it), rather than at the end of the line. Only
    exit comments (x_exit etc.) can be Blocks. Its fields are filled in as
    for any text (see OsbyteCall.text())."""


class Osbyte:
    """How to comment a call to one OSBYTE (an entry in osbyte_calls). Each
    text is a string with fields, or a function (see the top of this
    module).

    The call itself:
        call        the comment (when X isn't known, or none of the below apply)
        x_choices   {value of X: comment}
        x_names     {value of X: name}, for a comment made with...
        x_named     ...this text, using {name}
        x_other     the comment when X is known, but not in x_choices or x_names
        suffix      added to the end of the comment
    Its results:
        x_exit, y_exit  comments on the next use of X or Y after the call
        xy_exit         a comment on the next use of either
    Where X and Y are set:
        x_enum      (dictionary, comment): name the value of X with the
                    constant from the dictionary, and comment on it (with
                    acornhelpers.enum_lookup())
        x_format    show X's value with binary, char or decimal
        x_note, y_note  (where, comment): comment on where X or Y is set:
                    "operand" (the operand of the load), "load" (the
                    instruction that loads it) or "adjust" (the instruction
                    that last changed it)
    Or:
        handler     a function taking the OsbyteCall, which does all of the
                    commenting itself
    """

    def __init__(self, call=None, *, x_choices=None, x_names=None, x_named=None, x_other=None, suffix="",
                 x_exit=None, y_exit=None, xy_exit=None,
                 x_enum=None, x_format=None, x_note=None, y_note=None,
                 handler=None):
        self.call = call
        self.x_choices = x_choices or {}
        self.x_names = x_names or {}
        self.x_named = x_named
        self.x_other = x_other
        self.suffix = suffix
        self.x_exit = x_exit
        self.y_exit = y_exit
        self.xy_exit = xy_exit
        self.x_enum = x_enum
        self.x_format = x_format
        self.x_note = x_note
        self.y_note = y_note
        self.handler = handler

    def describe(self, call):
        """Comment on the call (an OsbyteCall): where X and Y are set, if A
        is known optimistically (which osbyte_hook() has checked); and the
        call and its results, only if A is known for certain. A handler does
        all of it instead, and checks call.sure itself."""
        if self.handler is not None:
            self.handler(call)
            return

        # Where X and Y are set
        if self.x_enum is not None and call.x_addr_optimistic is not None:
            enum_lookup(call.x_addr_optimistic, *self.x_enum)
        if self.x_format is not None and call.x_operand is not None:
            self.x_format(call.x_operand)
        for register, note in [("x", self.x_note), ("y", self.y_note)]:
            if note is not None:
                where, text = note
                auto_comment(getattr(call, register + "_" + where), text, align=Align.INLINE)

        # The call and its results, only if it's surely this OSBYTE
        if not call.sure:
            return
        call.comment(self.call_comment(call))
        for runtime_addr, text in [(call.x_next_use, self.x_exit), (call.y_next_use, self.y_exit), (call.xy_next_use, self.xy_exit)]:
            if text is not None and runtime_addr is not None:
                call.exit_comment(runtime_addr, call.text(text))

    def call_comment(self, call):
        """The comment for the call itself, chosen by X's value (if it's
        known for certain): from x_choices, then x_names (with x_named),
        then x_other, otherwise 'call'. Its fields are filled in, and the
        suffix added."""
        x = call.x
        name = None
        if x is None:
            template = self.call
        elif x in self.x_choices:
            template = self.x_choices[x]
        elif x in self.x_names:
            template, name = self.x_named, self.x_names[x]
        elif self.x_other is not None:
            template = self.x_other
        else:
            template = self.call
        return call.text(template, name) + self.suffix


def count(n, singular, plural):
    """A number with its unit, e.g. '1 line' or '3 lines' (n can be a
    string, e.g. 'Y lines')."""
    return utils.count_with_units(n, singular, plural)


# ****************************************************************************
# Irregular OSBYTEs: those whose comments need more than a table entry
# ****************************************************************************

def osbyte_rw(x_binary_addr, y_binary_addr):
    """For the OSBYTEs that read or write an OS variable: whether the call
    reads, writes or does both ("Read", "Write" or "Read/Write"), and the
    value written (if known, otherwise None), from the binary addresses of
    the immediate operands that set X and Y (or None).

    These OSBYTEs set the variable to (its old value AND Y) EOR X, so Y=0
    writes X, and X=0 with Y=&FF only reads it."""
    com = "Read/Write"
    write_value=None
    if y_binary_addr is not None:
        if memory_binary[y_binary_addr] == 0:
            com = "Write"
            if x_binary_addr is not None:
                write_value = memory_binary[x_binary_addr]
        elif x_binary_addr is not None:
            if (memory_binary[x_binary_addr] == 0) and (memory_binary[y_binary_addr] == 255):
                com = "Read"

    return (com, write_value)

def format_osbyte_rw(x_addr, y_addr, comment_name):
    """The comment for a call that reads or writes an OS variable (see
    osbyte_rw()), e.g. 'Write user flag byte, value X=5', for the
    variable's description."""
    com, write_value = osbyte_rw(x_addr, y_addr)
    result = com + " " + comment_name
    if write_value is not None:
        result += ", value X=" + str(write_value)

    return result

def key_name(key):
    """The name of a key, in quotes, from its INKEY number as a byte (see
    inkey_enum), e.g. "'SPACE'"; or "an unknown" (for "an unknown key")."""
    if key in inkey_enum:
        # (Without the 'inkey_key_' at the start of the name)
        return "'" + inkey_enum[key][10:].upper() + "'"
    return "an unknown"

def append_bit_string(str, x, bit, result1, result0):
    """Add to 'str' (separated by '; ') result1 if the bit of x is set, or
    result0 if it's clear, and return it."""
    if len(str) > 0:
        str += "; "
    if (x & (1<<bit)) == 0:
        str += result0
    else:
        str += result1
    return str

def read_os_version(call):
    """OSBYTE 0: with X=0, BRK with the OS version as the error message;
    otherwise, read the OS version into X, which is explained where it's
    next used."""
    if not call.sure:
        return
    com = "Read OS version number (if X non-zero), or BRK and print OS version (if X=0)"
    if call.x is not None:
        if call.x == 0:
            com = "Execute BRK and print OS version (X=0)"
        else:
            com = "Read OS version number into X"
            auto_comment(call.x_next_use,
"""X is the OS version number:
    X=0, OS 1.00 (Early BBC B or Electron OS 1.00)
    X=1, OS 1.20 or American OS
    X=2, OS 2.00 (BBC B+)
    X=3, OS 3.2/3.5 (Master 128)
    X=4, OS 4.0 (Master Econet Terminal)
    X=5, OS 5.0 (Master Compact)""", indent=1)
    call.comment(com, show_blank=True)

def select_output_stream(call):
    """OSBYTE 3: choose where characters written with OSWRCH go. Each bit of
    X turns an output on or off, so X is shown in binary, and its bits are
    described if it's known."""
    if not call.sure:
        return
    com = "Select output stream based on X"
    if call.x_operand is not None:
        binary(call.x_operand)

    if call.x is not None:
        x = call.x
        com += ": "
        # (Bits 5 and 7 aren't described)
        bit_str = ""
        bit_str = append_bit_string(bit_str, x, 0, "enable RS232 output", "disable RS232 output")
        bit_str = append_bit_string(bit_str, x, 1, "disable VDU driver", "enable VDU driver")
        bit_str = append_bit_string(bit_str, x, 2, "disable printer output", "enable printer output")
        bit_str = append_bit_string(bit_str, x, 3, "enable printer despite CTRL-B/C state", "disable printer despite CTRL-B/C state")
        bit_str = append_bit_string(bit_str, x, 4, "disable SPOOLed output", "enable SPOOLed output")
        bit_str = append_bit_string(bit_str, x, 6, "disable printer output unless VDU 1 first", "enable printer output even without VDU 1 first")
        com += bit_str

    call.comment(com)

    # Post exit:
    call.exit_comment(call.x_next_use, "X is the previous output stream status byte")

def set_printer_ignore_character(call):
    """OSBYTE 6: set the character the printer ignores to X, which is shown
    as a character."""
    if not call.sure:
        return
    com = "Set printer ignore character to "
    if call.x is not None:
        com += "X=" + str(call.x)
        if call.x_operand is not None:
            char(call.x_operand)
    else:
        com += "X"
    call.comment(com)

    # Post exit:
    call.exit_comment(call.x_next_use, "X is the previous printer ignore character")

def keyboard_scan(call):
    """OSBYTE &79: with X >= &80, test whether the key with internal key
    number X EOR &80 is pressed; otherwise, scan the keyboard from internal
    key number X.

    Where X is set, the key is named with its INKEY constant (see
    inkey_enum), e.g. 'ldx #(255 - inkey_key_space) EOR 128': the INKEY
    number of the key with internal key number k is -(k+1), which is 255-k
    as a byte."""
    # Where X is set (optimistically): name the key
    if call.x_addr_optimistic is not None:
        key = memory_binary[call.x_addr_optimistic]
        if key >= 0x80:
            # (255-key is 127-k, so the EOR adds 128 back, giving 255-k)
            inkey_key = (255-key) ^ 0x80
            if inkey_key in inkey_enum:
                constant(inkey_key, inkey_enum[inkey_key])
                key_exp = make_eor(make_subtract(255, inkey_enum[inkey_key]), 128)
                auto_expr(call.x_operand, key_exp)
                auto_comment(call.x_operand, "X=internal key number EOR 128", align=Align.INLINE)
        else:
            inkey_key = 255-key
            if inkey_key in inkey_enum:
                constant(inkey_key, inkey_enum[inkey_key])
                key_exp = make_subtract(255, inkey_enum[inkey_key])
                auto_expr(call.x_operand, key_exp)
                auto_comment(call.x_operand, "X=internal key number", align=Align.INLINE)

    if not call.sure:
        return
    com = "Keyboard scan, or test for a specific key"
    many_key_scan = False
    one_key_scan = ""
    if call.x is not None:
        key = call.x
        if key >= 0x80:
            inkey_key = (255-key) ^ 0x80
            com = "Test for " + key_name(inkey_key) + " key pressed (X=%d)" % key
            one_key_scan = key_name(inkey_key)
        else:
            inkey_key = 255-key
            com = "Keyboard scan starting from " + key_name(inkey_key) + " key (X=%d)" % key
            many_key_scan = True
    call.comment(com)

    # Post exit:
    if call.x_next_use:
        com = "X is either the internal key number (0-127) pressed (for a keyboard scan), or the top bit is the key state (when testing a specific key)"
        if one_key_scan != "":
            com = "X has top bit set if " + one_key_scan + " pressed"
        elif many_key_scan:
            com = "X is the internal key number (0-127) if a key is pressed, or " + hex2(0xff) + " otherwise"
        call.exit_comment(call.x_next_use, com)

def read_buffer_status_or_adc(call):
    """OSBYTE &80: with X=0, read the last ADC channel converted and the
    joystick fire buttons; with X=1 to 127, read ADC channel X; with X >= &80,
    read how full buffer 255-X is (see negative_buffer_actions): the number
    of characters in an input buffer (X=&FF or &FE), or of spaces left in an
    output buffer."""
    if not call.sure:
        return
    com = "Read buffer status or ADC channel"
    input_buffer = None
    output_buffer = None
    is_last_channel = False
    is_read_last_value = False
    if call.x is not None:
        x_action = call.x
        if x_action == 0:
            com = "Read the channel number last used for an ADC conversion and joystick fire buttons (X=0)"
            is_last_channel = True
        elif x_action < 128:
            com = "Read the ADC conversion value for channel X=%d" % (x_action)
            is_read_last_value = True
        else:
            if (255-x_action) in buffer_names:
                if x_action >= 254:
                    input_buffer = buffer_names[255-x_action]
                else:
                    output_buffer = buffer_names[255-x_action]

            if x_action in negative_buffer_actions:
                com = negative_buffer_actions[x_action]
    call.comment(com)

    # Post exit:
    if call.x_next_use:
        if input_buffer:
            call.exit_comment(call.x_next_use, "X is the number of characters in " + input_buffer)
        elif output_buffer:
            call.exit_comment(call.x_next_use, "X is the number of spaces remaining in " + output_buffer)
    if is_last_channel:
        if call.x_next_use:
            call.exit_comment(call.x_next_use, "X has the joystick fire buttons status in the lower two bits: bit 0=left button, bit 1=right button")
        if call.y_next_use:
            call.exit_comment(call.y_next_use, "Y is the last ADC channel number to complete conversion")

    if is_read_last_value:
        if call.x_next_use or call.y_next_use:
            call.exit_comment(call.xy_next_use, "X and Y contain the ADC value read (low,high)")

def read_key(call):
    """OSBYTE &81 (INKEY): with Y >= &80, test the key whose INKEY number (as
    a byte) is X, or with X=0, read the machine type; otherwise, wait up to
    X+256*Y centiseconds for a key press."""
    # Comment on setting X: an INKEY key number, unless X=0 (read machine type)
    if call.y_addr_optimistic is not None:
        if memory_binary[call.y_addr_optimistic] >= 0x80:
            if call.x_addr_optimistic is not None:
                x = memory_binary[call.x_addr_optimistic]
                enum_lookup(call.x_addr_optimistic, inkey_enum, None if x == 0 else "X=inkey key value")

    if not call.sure:
        return
    com = "Read key within time limit, or read a specific key, or read machine type"
    is_read_machine_type = False
    is_read_ascii_key = False
    is_checking_specific_key_pressed = False
    if call.y is not None:
        if call.y >= 0x80:
            com = "Read a specific key (or read machine type)"
            if call.x is not None:
                key = call.x
                if key == 0:
                    com = "Read the machine type"
                    is_read_machine_type = True
                else:
                    com = "Is the " + key_name(key) + " key pressed?"
                    is_checking_specific_key_pressed = True
        else:
            com = "Wait for a key press with a time limit"
            is_read_ascii_key = True
            if call.x is not None:
                com = "Wait for a key press within " + count(call.x + 256*call.y, "centisecond", "centiseconds")

    call.comment(com)

    # Post exit:
    if call.x_next_use:
        if is_read_machine_type:
            auto_comment(call.x_next_use,
"""X is the machine type:
    X=0, BBC microcomputer OS 0.10
    X=1, Acorn Electron OS 1.00
    X=255, BBC microcomputer OS 1.00 or 1.20
    X=254, BBC microcomputer OS A1.0 (USA)
    X=253, Master 128 OS 3.20 or 3.50
    X=251, BBC B+ OS 2.00
    X=250, Acorn Business Computer OS 1.00 or 2.00
    X=247, Master Econet Terminal OS 4.00
    X=245, Master Compact OS 5.10""", indent=1, show_blank=True)
        elif is_read_ascii_key:
            auto_comment(call.x_next_use, "X is the ASCII value of the key pressed (assuming Y=0)")

    if call.y_next_use:
        if is_read_ascii_key:
            call.exit_comment(call.y_next_use, "Y is zero if key pressed; " + hex2(0xff) + " if no key pressed; " + hex2(0x1b) + " if ESCAPE pressed")

    if is_checking_specific_key_pressed:
        if call.x_next_use or call.y_next_use:
            call.exit_comment(call.xy_next_use, "X and Y contain " + hex2(0xff) + " if the key is pressed")

def opt(call):
    """OSBYTE &8B: *OPT X,Y, described from opt_descriptions (keyed by e.g.
    "1,2"), or for *OPT 0 and *OPT 3 here."""
    if not call.sure:
        return
    x = "X" if call.x is None else str(call.x)
    y = "Y" if call.y is None else str(call.y)
    key = x+","+y
    com = "*OPT " + key
    if key in opt_descriptions:
        com += ": " + opt_descriptions[key]
    elif x == "0":
        com += ": Reset all options for current filing system"
    elif x == "3":
        com += ": if TAPE, set interblock gap to " + count(y, "tenth of a second", "tenths of a second")
    call.comment(com)

def tv(call):
    """OSBYTE &90: *TV X,Y. X is the number of lines to move the display (a
    signed byte: &80 or more moves it down), and Y=0 turns interlace on."""
    if not call.sure:
        return
    suffix = ""
    if call.x is not None:
        x = call.x
        if x >= 128:
            suffix = "shift display down " + count(256-x, "line", "lines")
        elif x != 0:
            suffix = "shift display up " + count(x, "line", "lines")
        x = str(x)
    else:
        x = "X"

    if call.y is not None:
        y = str(call.y)
        if len(suffix)>0:
            suffix += ", "
        if y == "0":
            suffix += "turn interlace on"
        else:
            suffix += "turn interlace off"
    else:
        y = "Y"

    if len(suffix)>0:
        suffix = " " + suffix
    call.comment("*TV " + x + "," + y + suffix)

    # Post exit:
    call.exit_comment(call.x_next_use, "X is the previous screen shift setting")
    call.exit_comment(call.y_next_use, "Y is the previous interlace option (0=interlace on, 1=off)")

def read_or_write_memory_mapped_io(call):
    """OSBYTEs &92 to &97: read (the even ones) or write (the odd ones) the
    byte at offset X in FRED (&FC00), JIM (&FD00) or SHEILA (&FE00). The value
    written is Y, and the value read is returned in Y."""
    if not call.sure:
        return
    com = read_or_write_memory_mapped_device[call.a]
    if call.x is not None:
        mmio_address = read_or_write_memory_mapped_address[call.a] + call.x
        com += " address " + config.get_assembler().hex4(mmio_address)
    else:
        com += " address " + config.get_assembler().hex4(read_or_write_memory_mapped_address[call.a]) + " + X"

    is_writing = call.a in (0x93, 0x95, 0x97)
    if is_writing:
        if call.y is not None:
            com += ", value Y=" + str(call.y)
        else:
            com += ", value Y"
    else:
        com += " into Y"

    call.comment(com)

    # Post exit:
    if not is_writing:
        call.exit_comment(call.y_next_use, "Y is the byte read")

def video_ula_control(call):
    """The comment for OSBYTE &9A with a known X (its x_other): what X sets
    in the video ULA's control register (at &FE20): the number of columns
    (bits 2-3: 10, 20, 40 or 80), the clock rate (bit 4: 1 or 2 MHz, for
    modes 4-7 or 0-3), the cursor's segments (bits 5-7, each drawn if its
    bit is set: segment 0 is bit 7), teletext (bit 1) and whether the
    flashing colours are inverted (bit 0). E.g. for mode 0's &9C: 'Set video
    ULA control: 80 columns, 2 MHz clock, cursor segment 0, and reset flash
    cycle'."""
    val = call.x
    columns = (10, 20, 40, 80)[(val >> 2) & 3]
    clock = 2 if val & 0x10 else 1
    segments = [str(segment) for segment, bit in ((0, 0x80), (1, 0x40), (2, 0x20)) if val & bit]
    if not segments:
        cursor = "no cursor"
    elif len(segments) == 1:
        cursor = "cursor segment " + segments[0]
    else:
        cursor = "cursor segments " + ", ".join(segments[:-1]) + " and " + segments[-1]
    com = "Set video ULA control: {0} columns, {1} MHz clock, {2}".format(columns, clock, cursor)
    if val & 2:
        com += ", teletext"
    if val & 1:
        com += ", flashing colours inverted"
    com += ", and reset flash cycle"
    return com

def acia_control(call):
    """OSBYTE &9C: read or write the 6850 ACIA's control register (and the
    OS's copy of it), as for an OS variable (see osbyte_rw()). X is shown in
    binary, and the value written is described if it's known."""
    if call.x_addr_optimistic is not None:
        binary(call.x_operand)
    if not call.sure:
        return
    _, write_value = osbyte_rw(call.x_addr, call.y_addr)
    com = format_osbyte_rw(call.x_addr, call.y_addr, "6850 (ACIA) control register")
    if write_value is not None:
        # The control register's fields: bits 0-1 the counter divide
        # (or master reset), bits 2-4 the word format, bits 5-6 the
        # transmit control, and bit 7 the receive interrupt enable
        com += ": "
        com += { 0: "divide counter by 1",
                 1: "divide counter by 16",
                 2: "divide counter by 64 (default for RS423)",
                 3: "master reset",
                 }[write_value & 3]
        com += "; "
        com += { 0: "7 bit word, even parity, 2 stop bits",
                 1: "7 bit word, odd parity, 2 stop bits",
                 2: "7 bit word, even parity, 1 stop bit",
                 3: "7 bit word, odd parity, 1 stop bit",
                 4: "8 bit word, 2 stop bits",
                 5: "8 bit word, 1 stop bit",
                 6: "8 bit word, even parity, 1 stop bit",
                 7: "8 bit word, odd parity, 1 stop bit"
                 }[(write_value // 4) & 7]
        com += "; "
        com += { 0: "RTS low, transmit interrupt disabled",
                 1: "RTS low, transmit interrupt enabled",
                 2: "RTS high, transmit interrupt disabled",
                 3: "RTS low, break level on data output, transmit interrupt disabled"
                 }[(write_value // 32) & 3]
        if (write_value & 128) != 0:
            com += "; enables the receive data register full, over-run, or DCD transition interrupts."
    call.comment(com)

    # Post exit:
    call.exit_comment(call.x_next_use, "X is the previous value of the control register")

def read_vdu_variable(call):
    """OSBYTE &A0: read VDU variable X into X, and the next one into Y,
    named from vdu_variables."""
    if not call.sure:
        return
    com = "Read VDU variable X"
    var1 = "the VDU variable"
    var2 = "next VDU variable"
    if call.x is not None:
        by = call.x
        if by in vdu_variables:
            var1 = vdu_variables[by]
            com ="Read the " + var1
            if (by+1) in vdu_variables:
                var2 = vdu_variables[by+1]
        com += " (VDU variable X=" + str(by) + ")"

    call.comment(com)

    # Post exit:
    call.exit_comment(call.x_next_use, "X is the " + var1)
    call.exit_comment(call.y_next_use, "Y is the " + var2)

def read_cmos(call):
    """OSBYTE &A1 (Master and Compact): read CMOS RAM (or EEPROM) byte X
    into Y, named from cmos_ram; on the Compact, X=255 reads the EEPROM's
    size instead."""
    if not call.sure:
        return
    com = "Master and Compact: Read CMOS RAM/EEPROM byte X"
    is_get_size = False
    name_of_byte = ""
    if call.x is not None:
        by = call.x

        if by == 255:
            com = "Compact only: Determine if the EEPROM is 128 or 256 bytes long (X=255)"
            is_get_size = True
        else:
            if by in cmos_ram:
                name_of_byte = "'" + cmos_ram[by] + "'"
                com = "Master and Compact: Read the " + name_of_byte + " byte from CMOS RAM/EEPROM (X=" + str(by) + ")"
            else:
                com = "Master and Compact: Read CMOS RAM/EEPROM byte X=" + str(by)

    call.comment(com)

    # Post exit:
    if call.y_next_use:
        if is_get_size:
            call.exit_comment(call.y_next_use, "Y=0 means no EEPROM present; Y=127 means 128 byte EEPROM; Y=255 means 256 byte EEPROM present")
        else:
            if name_of_byte == "":
                call.exit_comment(call.y_next_use, "Y is the byte value read from the CMOS RAM/EEPROM")
            else:
                call.exit_comment(call.y_next_use, "Y is the %s byte read from the CMOS RAM/EEPROM" % name_of_byte)

def write_cmos(call):
    """OSBYTE &A2 (Master and Compact): write Y to CMOS RAM (or EEPROM) byte
    X, named from cmos_ram."""
    if not call.sure:
        return
    com = "Master and Compact: Write to CMOS RAM/EEPROM byte X"
    if call.x is not None:
        by = call.x
        if by in cmos_ram:
            name_of_byte = "'" + cmos_ram[by] + "'"
            com = "Master and Compact: Write to the " + name_of_byte + " byte from CMOS RAM/EEPROM (X=" + str(by) + ")"
        else:
            com = "Master and Compact: Write to CMOS RAM/EEPROM byte X=" + str(by)
    com += " with value Y"
    if call.y is not None:
        com += "=" + str(call.y)

    call.comment(com)

def os_variable(call):
    """OSBYTEs &A6 to &FF: read or write an OS variable (see osbyte_rw()),
    named from os_variable_names. X returns the variable's value (its old
    value, for a write), and Y the next variable's (OSBYTE number+1's).
    A few have comments of their own: &C8 (ESCAPE and BREAK effects), &C9
    (keyboard disable), &E5 (ESCAPE key status) and &FF (the startup
    options, shown in binary and explained where X is next used)."""
    # Where X is set (optimistically)
    if call.a in (0xc6, 0xc7):
        auto_comment(call.x_adjust, "X=File handle", align=Align.INLINE)
    if call.a == 0xff:
        # If writing the startup byte, show it in binary
        _, write_value = osbyte_rw(call.x_addr_optimistic, call.y_addr_optimistic)
        if write_value is not None and call.x_operand is not None:
            binary(call.x_operand)

    if not call.sure:
        return
    _, write_value = osbyte_rw(call.x_addr, call.y_addr)

    name = os_variable_names[call.a]
    next_name = os_variable_names.get(call.a + 1)
    next_next_name = os_variable_names.get(call.a + 2)

    # Exceptions: for a write of a known value, &C8, &C9 and &E5 say what it
    # does instead (the comments on X after the call still name the
    # variable)
    skip_normal_comment = False
    if call.a == 0xc8:
        # Bit 0 disables ESCAPE; any other bit set clears memory on BREAK
        if write_value is not None:
            if write_value & 1:
                result = "Disable ESCAPE action, "
            else:
                result = "Set normal ESCAPE action, "
            if (write_value & 0xfe) == 0:
                result += "set normal BREAK action"
            else:
                result += "clear memory on BREAK"
            call.comment(result + " (X=%d)" % write_value)
            skip_normal_comment = True
    elif call.a == 0xc9:
        result = "Enable/Disable keyboard (for Econet)"
        if write_value is not None:
            if write_value == 0:
                result = "Enable keyboard (for Econet)"
            else:
                result = "Disable keyboard (for Econet)"
        call.comment(result)
        skip_normal_comment = True
    elif call.a == 0xe5 and write_value is not None:
        if write_value == 0:
            result = "Set ESCAPE key status to normal action"
        else:
            result = "Set ESCAPE key to produce ASCII code " + str(write_value)
        call.comment(result)
        skip_normal_comment = True

    if not skip_normal_comment:
        call.comment(format_osbyte_rw(call.x_addr, call.y_addr, name))

    # Post exit:
    # Exit parameters specify low byte for a corresponding high byte (e.g.
    # OSBYTE &A6 returns the address of the OS variables, low byte in X and
    # high byte in Y).
    if next_name == name + " (high byte)":
        name += " (low byte)"
    if next_name and (next_next_name == next_name + " (high byte)"):
        next_name += " (low byte)"
    if call.x_next_use:
        if write_value is None:
            call.exit_comment(call.x_next_use, "X=value of " + name)
        else:
            call.exit_comment(call.x_next_use, "X=old value of " + name)
    if call.y_next_use:
        if next_name:
            call.exit_comment(call.y_next_use, "Y=value of " + next_name)

    # Exceptions
    if call.a == 0xff:
        auto_comment(call.x_next_use,
"""X is the startup option byte:
    bits 0 to 2     screen MODE selected following reset
    bit 3           if clear reverse action of SHIFT+BREAK
    bits 4 and 5    used to set disc drive timings (see below)
    bit 6           not used by OS (reserved for future applications)
    bit 7           if clear select NFS, if set select DFS

Disc drive timing links:
|                           |                8271                 |          1770           |          1772           |
|---------------------------|-------------------------------------|-------------------------|-------------------------|
| b5 | b4 | link 3 | link 4 | step time | settle time | head load | step time | settle time | step time | settle time |
|----|----|--------|--------|-----------|-------------|-----------|-----------|-------------|-----------|-------------|
|  0 | 0  | 1      | 1      | 4         | 16          | 0         | 6         | 30          | 6         | 15          |
|  0 | 1  | 1      | 0      | 6         | 16          | 0         | 12        | 30          | 12        | 15          |
|  1 | 0  | 0      | 1      | 6         | 50          | 32        | 20        | 30          | 2         | 15          |
|  1 | 1  | 0      | 0      | 24        | 20          | 64        | 30        | 30          | 3         | 15          |
|---------------------------------------------------------------------------------------------------------------------|""", indent=1, show_blank=True, word_wrap=False)


# ****************************************************************************
# The OSBYTEs
# ****************************************************************************

# How to comment each OSBYTE, by number (the value of A at the call). An
# OSBYTE that isn't here but is in osbyte_extra_descriptions (mostly those of
# other ROMs and add-ons) gets just a one-line description, when A is known
# for certain; others get no comment, though their number is still named if
# it's in osbyte_enum.
osbyte_calls = {
    0x00: Osbyte(handler=read_os_version),

    0x01: Osbyte("Set user flag byte to {x}",
        x_exit="X is the previous value of the user flag byte"),

    0x02: Osbyte("Select input stream X (0=keyboard, 1=RS232, 2=both)",
        x_choices={
            0: "Select keyboard as input stream with RS232 disabled (X=0)",
            1: "Select RS232 as input stream with keyboard disabled (X=1)",
            2: "Select keyboard as input stream with RS232 enabled (X=2)"},
        x_exit="X is the previous input stream (0=keyboard, 1=RS232)"),

    0x03: Osbyte(handler=select_output_stream),

    0x04: Osbyte("Enable/disable cursor editing based on X",
        x_choices={
            0: "Enable cursor editing (X=0)",
            1: "Disable cursor editing (edit keys give ASCII 135-139) (X=1)",
            2: "Disable cursor editing (edit keys act as soft keys f11 to f15) (X=2)",
            3: "Cursor editing keys and COPY simulate a joystick (Master Compact only) (X=3)"},
        x_exit=Block(
"""X is the previous status of the cursor editing keys:
    X=0, cursor editing was enabled (the default setting)
    X=1, cursor editing was disabled, edit keys gave ASCII codes (135 to 139)
    X=2, cursor editing was disabled, edit keys acted as soft keys (11 to 15)
    X=3, cursor editing keys and COPY simulated a joystick (Master Compact only)""")),

    0x05: Osbyte("Select printer destination based on X",
        x_choices={
            0: "Select printer destination: Ignore printer output (X=0)",
            1: "Select printer destination: Parallel output (X=1)",
            2: "Select printer destination: RS423 output (X=2)",
            3: "Select printer destination: User printer routine (X=3)",
            4: "Select printer destination: Net printer (X=4)"},
        x_other="Select printer destination: User printer routine (X>4)",
        x_exit=Block(
"""X is the previous printer destination:
    X=0, printer sink (printer output ignored)
    X=1, parallel output
    X=2, RS423 output (will act as sink if RS423 is enabled using OSBYTE 3)
    X=3, user printer routine
    X=4, net printer
    X=5+, user printer routine""")),

    0x06: Osbyte(handler=set_printer_ignore_character),

    0x07: Osbyte("Set serial receive rate based on X",
        x_enum=(baud_rate_enum, "X=baud rate"),
        x_names=baud_rates, x_named="Set serial receive rate to {name} (X={x})",
        xy_exit=Block(
"""X and Y contain the previous serial ULA register contents (not Electron).
    Bits 0-2 = transmit rate
    Bits 3-5 = receive rate
    Bit 6    = RS423 in control (if set) / Tape in control (if clear)
    Bit 7    = cassette motor""")),

    0x08: Osbyte("Set serial transmission rate based on X",
        x_enum=(baud_rate_enum, "X=baud rate"),
        x_names=baud_rates, x_named="Set serial transmission rate to {name} (X={x})",
        xy_exit=Block(
"""X and Y contain the previous serial ULA register contents (not Electron).
    Bits 0-2 = transmit rate
    Bits 3-5 = receive rate
    Bit 6    = RS423 in control (if set) / Tape in control (if clear)
    Bit 7    = cassette motor""")),

    0x09: Osbyte("Set 'mark' duration of flashing colours to X fiftieths of a second",
        x_choices={0: "Set 'mark' duration of flashing colours to infinity (X=0)"},
        x_other=lambda call: "Set 'mark' duration of flashing colours to X=" + count(call.x, "vsync (fiftieth of a second)", "vsyncs (fiftieths of a second)"),
        x_exit="X is the previous mark duration (in fiftieths of a second)"),

    0x0a: Osbyte("Set 'space' duration of flashing colours to X fiftieths of a second",
        x_choices={0: "Set 'space' duration of flashing colours to infinity (X=0)"},
        x_other=lambda call: "Set 'space' duration of flashing colours to X=" + count(call.x, "vsync (fiftieth of a second)", "vsyncs (fiftieths of a second)"),
        x_exit="X is the previous space duration (in fiftieths of a second)"),

    0x0b: Osbyte("Set keyboard auto-repeat delay to X centiseconds",
        x_choices={0: "Disable keyboard auto-repeat (X=0)"},
        x_other=lambda call: "Set keyboard auto-repeat delay to X=" + count(call.x, "centisecond", "centiseconds"),
        x_exit="X is the previous keyboard auto-repeat delay (in centiseconds)"),

    0x0c: Osbyte("Set keyboard auto-repeat interval to X centiseconds",
        x_choices={0: "Reset keyboard delay and repeat to default values (X=0)"},
        x_other=lambda call: "Set keyboard auto-repeat interval to X=" + count(call.x, "centisecond", "centiseconds"),
        x_exit="X is the previous keyboard auto-repeat interval (in centiseconds)"),

    0x0d: Osbyte("Disable event X",
        x_enum=(event_enum, "X=event number"),
        x_names=event_names, x_named="Disable '{name}' event (X={x})",
        x_exit="X is the previous value of the event enable flag (0=disabled, non-zero=enabled)"),

    0x0e: Osbyte("Enable event X",
        x_enum=(event_enum, "X=event number"),
        x_names=event_names, x_named="Enable '{name}' event (X={x})",
        x_exit="X is the previous event enable flag (0=disabled, non-zero=enabled)"),

    0x0f: Osbyte("Flush all buffers (X=0), or just input buffers (X non-zero)",
        x_choices={0: "Flush all buffers (X=0)"},
        x_other="Flush input buffers (X non-zero)"),

    0x10: Osbyte("Select number of ADC channels based on X",
        x_choices={0: "Disable ADC channel sampling (X=0)"},
        x_other=lambda call: "Select " + count(call.x, "ADC channel", "ADC channels") + " (X=%d)" % call.x,
        x_exit="X is the previous ADC channel 1-4 or zero if disabled"),

    0x11: Osbyte("Force ADC conversion on channel {xe}"),

    0x12: Osbyte("Reset function keys"),

    0x13: Osbyte("Wait for vertical sync"),

    0x14: Osbyte("Implode or Explode character definition RAM based on X",
        x_choices={
            0: "Implode character definition RAM, can redefine characters 128-159 (X=0)",
            1: "Explode character definition RAM (one extra page), can redefine characters 128-191 (X=1)",
            2: "Explode character definition RAM (two extra pages), can redefine characters 128-223 (X=2)",
            3: "Explode character definition RAM (three extra pages), can redefine characters 128-255 (X=3)",
            4: "Explode character definition RAM (four extra pages), can redefine characters 128-255 and 32-63 (X=4)",
            5: "Explode character definition RAM (five extra pages), can redefine characters 128-255 and 32-95 (X=5)",
            6: "Explode character definition RAM (six extra pages), can redefine all characters 32-255 (X=6)"},
        x_exit="X is the new OSHWM (high byte)"),

    0x15: Osbyte("Flush specific buffer X",
        x_enum=(buffer_enum, "X=buffer number"),
        x_names=buffer_names, x_named="Flush {name} (X={x})",
        x_other="Flush unknown buffer (X={x})"),

    0x16: Osbyte("Electron and Master: Increment polling semaphore"),

    0x17: Osbyte("Electron and Master: Decrement polling semaphore"),

    0x18: Osbyte("Electron: External sound (with parameter X)"),

    0x19: Osbyte("Master only: Restore a group of default font definitions based on X",
        x_choices=font_definitions),

    0x44: Osbyte("Master and B+ only: Test for sideways RAM",
        x_exit="Bits 0-3 of X indicate use of ROM numbers 4-7 as RAM"),

    0x45: Osbyte("Master and B+ only: Get sideways RAM allocation",
        x_exit="Bits 0-3 of X indicate ROM numbers 4-7 in use for extended addressing"),

    0x6b: Osbyte("Master, Compact & Electron: Select 1MHz bus (X=0) or cartridge (X=1)",
        x_choices={
            0: "Master, Compact & Electron: Selects the external bus (running at 1MHz on the Electron) (X=0)",
            1: "Master, Compact & Electron: Selects the internal bus running at 2MHz (X=1)"},
        x_other="Master, Compact & Electron: Selects the unknown bus X={x}"),

    0x6c: Osbyte("Master only: Select screen memory for direct access",
        x_choices={
            0: "Master only: Select main memory for screen memory direct access (X=0)",
            1: "Master only: Select shadow memory for screen memory direct access (X=1)"},
        x_other="Master only: Selects unknown screen memory bank X={x}"),

    0x6d: Osbyte("Master: Make temporary filing system permanent"),

    0x70: Osbyte("Master: Select main/shadow memory for VDU access",
        x_choices={
            0: "Master: Select main memory for MODE 0-7 and shadow memory for MODE 128-135 VDU access (X=0)",
            1: "Master: Select main memory for VDU access (X=1)",
            2: "Master: Select shadow memory for VDU access (X=2)"},
        x_other="Master: Select unknown screen memory bank for VDU access (X={x})",
        x_exit="X is the previous VDU access memory setting (0=main or shadow memory according to current mode, 1=main memory, 2=shadow memory)"),

    0x71: Osbyte("Master: Select main/shadow memory for display",
        x_choices={
            0: "Master: Select main memory for display in MODE 0-7 and shadow memory for MODE 128-135 (X=0)",
            1: "Master: Select main memory for display (X=1)",
            2: "Master: Select shadow memory for display (X=2)"},
        x_other="Master: Select unknown screen memory bank for display (X={x})",
        x_exit="X is the previous display memory setting (0=main/shadow memory according to current mode, 1=main memory, 2=shadow memory)"),

    0x72: Osbyte("B+ and Master only: Write shadow memory use (X=0 is always; X non-zero is no shadow memory for MODEs 0-7)",
        x_choices={0: "B+ and Master only: Select shadow memory always used (X=0)"},
        x_other="B+ and Master only: Select shadow memory except for MODEs 0-7 (X non-zero)",
        x_exit="X is the previous display memory setting (0=main/shadow memory according to current mode, 1=main memory, 2=shadow memory)"),

    0x73: Osbyte("Electron: Blank (X non-zero) or restore (X=0) palette",
        x_choices={0: "Electron: Restores the palette (X=0)"},
        x_other="Electron: Set palette colours to black (X non-zero)"),

    0x74: Osbyte("Electron only: Reset sound system"),

    0x75: Osbyte("Read VDU status byte",
        x_exit=Block(
"""X is VDU status byte:
    bit 0=printer output enabled by a VDU 2
    bit 1=scrolling disabled (cursor editing)
    bit 2=paged scrolling selected
    bit 3=software scrolling selected (text window)
    bit 4=shadow mode selected
    bit 5=text at graphics cursor (VDU 5)
    bit 6=two cursor editing mode
    bit 7=screen disabled via VDU 21""")),

    0x76: Osbyte("Reflect keyboard status in keyboard LEDs"),

    0x77: Osbyte("Close any *SPOOL and *EXEC files"),

    0x78: Osbyte("Write current keys pressed (X and Y)",
        x_note=("adjust", "X=key"), y_note=("adjust", "Y=key")),

    0x79: Osbyte(handler=keyboard_scan),

    0x7a: Osbyte("Keyboard scan starting from key 16",
        x_exit="X is key number if key is pressed, or {hex2[0xff]} otherwise"),

    0x7b: Osbyte("Printer driver going dormant"),

    0x7c: Osbyte("Clear escape condition",
        x_exit="X={hex2[0xff]} if there was an ESCAPE condition to clear, or zero otherwise"),

    0x7d: Osbyte("Set escape condition"),

    0x7e: Osbyte("Clear escape condition and perform escape effects",
        x_exit="X={hex2[0xff]} if there was an ESCAPE condition to clear, or zero otherwise"),

    0x7f: Osbyte("Check for EOF in file handle X",
        x_note=("adjust", "X=File handle"),
        x_exit="X is non-zero if reached end of file, zero otherwise"),

    0x80: Osbyte(handler=read_buffer_status_or_adc),

    0x81: Osbyte(handler=read_key),

    0x82: Osbyte("Read the filing system 'machine high order address'",
        xy_exit="X and Y contain the machine high order address (low, high)"),

    0x83: Osbyte("Read top of operating system RAM address (OSHWM)",
        xy_exit="X and Y contain the address of OSHWM (low, high)"),

    0x84: Osbyte("Read top of user memory (HIMEM)",
        xy_exit="X and Y contain the address of HIMEM (low, high)"),

    0x85: Osbyte("Read top of user memory for a given screen mode X",
        x_note=("load", "X=MODE number"),
        x_other="Read top of user memory for screen MODE {x}",
        xy_exit="X and Y contain the address (low, high)"),

    0x86: Osbyte("Read input cursor position (Sets X=POS and Y=VPOS)",
        x_exit="X is the horizontal text position ('POS')",
        y_exit="Y is the vertical text position ('VPOS')"),

    0x87: Osbyte("Read character at the text cursor, and current screen MODE",
        x_exit="X is the character at the text cursor",
        y_exit="Y is the current screen MODE (0-7)"),

    0x88: Osbyte("*CODE X,Y"),

    0x89: Osbyte("Switch cassette motor relay on or off, based on X",
        x_choices={0: "Switch cassette motor relay off (X=0)"},
        x_other="Switch cassette motor relay on (X non-zero)"),

    0x8a: Osbyte("Insert value {y} into buffer X",
        x_enum=(buffer_enum, "X=buffer number"),
        x_names=buffer_names, x_named="Insert value {y} into {name} (X={x})",
        x_other="Insert value {y} into unknown buffer (X={x})",
        suffix="; carry is clear if successful"),

    0x8b: Osbyte(handler=opt),

    0x8c: Osbyte("Select TAPE filing system",
        x_format=decimal,
        x_choices={
            0: "Select TAPE filing system at default 1200 baud (X=0)",
            3: "Select TAPE filing system at 300 baud (X=3)"},
        x_other="Select TAPE filing system at 1200 baud (X={x})"),

    0x8d: Osbyte("Select ROM filing system"),

    0x8e: Osbyte("Enter language ROM X",
        x_note=("adjust", "X=ROM number")),

    0x8f: Osbyte("Issue paged ROM service call",
        x_names=paged_rom_reasons, x_named="Issue paged ROM service call, {name}",
        x_other="Issue paged ROM service call, Reason X={x}",
        x_exit="X is zero if a paged ROM claimed the service call",
        y_exit="Y contains a return argument from the ROM service call"),

    0x90: Osbyte(handler=tv),

    0x91: Osbyte("Get character from input buffer",
        x_enum=(buffer_enum, "X=buffer number"),
        x_choices={
            0: "Get character from keyboard buffer",
            1: "Get character from RS423 input buffer"},
        suffix=" (C is set if the buffer is empty, otherwise Y=extracted character)",
        y_exit="Y is the character extracted from the buffer"),

    **{a: Osbyte(handler=read_or_write_memory_mapped_io) for a in range(0x92, 0x98)},

    0x98: Osbyte("Examine status of buffer X",
        x_enum=(buffer_enum, "X=buffer number"),
        x_names=buffer_names, x_named="Examine {name}",
        x_other="Examine status of unknown buffer",
        suffix=" (exits with carry clear on success)",
        y_exit="Y is: on BBC Micro: offset to next character to be read from address stored at ({hex2[0xfa]}, {hex2[0xfb]}); or Master, B+, Electron: the byte read"),

    0x99: Osbyte("Insert character {ye} into input buffer X",
        x_choices={
            0: "Insert character {ye} into keyboard buffer",
            1: "Insert character {ye} into RS423 input buffer"}),

    0x9a: Osbyte("Write X to video ULA control register and OS copy (BBC and Master only), and reset flash cycle",
        x_format=binary,
        x_other=video_ula_control),

    0x9b: Osbyte("Write X EOR 7 to video ULA palette register and OS copy (ignored on Electron)",
        x_other=lambda call: "Write %d EOR 7 = %d to video ULA palette register and OS copy (ignored on Electron)" % (call.x, call.x ^ 7)),

    0x9c: Osbyte(handler=acia_control),

    0x9d: Osbyte("Fast Tube BPUT value {xe} to file handle Y",
        y_note=("adjust", "Y=file handle")),

    0x9e: Osbyte("Read command/data byte from speech processor"),

    0x9f: Osbyte(lambda call: "Write " + ("byte Y" if call.y is None else "Y=%d" % call.y) + " to speech processor",
        y_note=("adjust", "Y=byte to write")),

    0xa0: Osbyte(handler=read_vdu_variable),

    0xa1: Osbyte(handler=read_cmos),

    0xa2: Osbyte(handler=write_cmos),

    0xa3: Osbyte("Reserved for application software"),

    0xa4: Osbyte("Check for 6502 code in paged ROM format, where XY is the address to check.",
        x_note=("operand", "X=Address of ROM format code to check (low byte)"),
        y_note=("operand", "Y=Address of ROM format code to check (high byte)")),

    0xa5: Osbyte("Read output cursor position (Master only)",
        x_exit="X=text cursor 'POS'",
        y_exit="Y=text cursor 'VPOS'"),

    # Read or write an OS variable
    **{a: Osbyte(handler=os_variable) for a in range(0xa6, 0x100)},
}


def osbyte_hook(runtime_addr, state, subroutine):
    """The subroutine hook for OSBYTE: comment on a call to it at
    runtime_addr, given the CPU state before it (see the top of this
    module). Does nothing if A isn't loaded with an immediate value before
    the call."""
    call = OsbyteCall(runtime_addr, state)
    if call.a is None:
        return

    # Name the OSBYTE number where A is set (optimistically)
    enum_lookup(call.a_addr, osbyte_enum)

    osbyte = osbyte_calls.get(call.a)
    if osbyte is not None:
        osbyte.describe(call)
    elif call.sure and call.a in osbyte_extra_descriptions:
        # We don't know much about these, but label them at least
        call.comment(osbyte_extra_descriptions[call.a] + " (see https://beebwiki.mdfs.net/OSBYTEs)")
