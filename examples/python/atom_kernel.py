"""The Acorn Atom's kernel ROM (#F000-#FFFF: its OS, and the BASIC
statements and COS commands it adds), as a test on a real program, with
acorn.atom(). It traces the code from the 6502's vectors, the default
vectors the kernel copies to #0204 on reset, its command tables, its tables
of plot routines and of OSWRCH's and OSRDCH's handlers, and the routines
BASIC calls, and classifies and names its tables. The strings it prints
after a call to #F7D1 are found by acorn.atom()'s hook, and its writes to
the 8255 are commented."""

from commands import *
import acorn
from acornatomtables import atom_os_calls, atom_kernel_routines

load(0xf000, "orig/atom_kernel.orig", "6502", "875e5e4bedde281bad88d8995fc58a20")
acorn.atom()

def command_table(table, prefix, names):
    """Mark one of the kernel's command tables (the BASIC statements it adds
    at #F000, or the COS's * commands at #F8BE): each entry is the
    command's name, then the address of its routine, high byte first (the
    high byte has bit 7 set, which ends the name), and an empty name ends
    the table. Each routine is traced, and named prefix + its name in lower
    case (or from 'names', {command name: name}, for a name that isn't one),
    e.g. 'command_plot'; the last entry's, for a command that isn't in the
    table, is named names[""]."""
    addr = table
    while True:
        a = addr
        while memory[a] < 0x80:
            a += 1
        command = bytes(memory[i] for i in range(addr, a)).decode("latin-1")
        if command:
            string(addr, len(command))
        name = names.get(command)
        if name is None:
            name = prefix + command.lower()
        code_ptr(a + 1, a, label_name=name)
        addr = a + 2
        if command == "":
            return

def low_byte_table(table, high, names):
    """Mark a table of the low bytes of routines' addresses, whose high byte
    is 'high' (as OSWRCH's and OSRDCH's tables of control code and key
    handlers are, with #FD): each routine is traced and named from 'names'
    (in order), and its byte written as the name's low byte."""
    for i, name in enumerate(names):
        entry(high * 256 + memory[table + i], name)
        byte(table + i)
        expr(table + i, make_lo(name))

# The 6502's vectors (NMI, reset, IRQ/BRK)
for addr, name in ((0xfffa, "nmi_handler"), (0xfffc, "reset"), (0xfffe, "irq_handler")):
    code_ptr(addr, label_name=name)

# The OS entry points and the kernel routines programs call (which
# acorn.atom() names as optional labels, so in a program they're only there
# if they're used, but they're all named here)
for addr, name, _ in atom_os_calls:
    entry(addr, acorn.os_call_name(name))
for addr, name, _, _ in atom_kernel_routines:
    entry(addr, name)

# The routines BASIC (or COS) calls, and nothing in the kernel does (from the
# commented disassembly of the kernel in floooh/emu-info)
entry(0xf02e, "test_array_variable")        # (starting at ?#5E in the text)
entry(0xf030, "test_array_variable_y")      # (starting at Y in the text)
entry(0xf04b, "interpret_command")          # the statements in basic_command_table
entry(0xf085, "assign_array_variable")
entry(0xf141, "command_run")
entry(0xfa6b, "jump_to_hex_address")        # (read from the input buffer)

# The default vectors, copied to #0204-#021B on reset (IRQVEC to SHTVEC):
# the kernel's own routines are named by acorn.atom(), and the others are in
# the utility and BASIC ROMs
label(0xff9a, "default_vectors")
for addr in range(0xff9a, 0xffb2, 2):
    code_ptr(addr)

# The command tables
label(0xf000, "basic_command_table")
command_table(0xf000, "command_", {"[": "command_assembler", "": "basic_unknown_command"})
label(0xf8be, "cos_command_table")
command_table(0xf8be, "star_", {"DOS\r": "dos", "": "cos_error"})

# The graphics modes: the page after the screen memory each of modes 1-4
# uses, the plot routine for each of modes 0-4 (whose low and high bytes are
# in two tables), and the byte CLEAR writes to #B000 for each
label(0xf6cf, "graphics_mode_end_pages")
byte(0xf6cf, 4)
label(0xf6d3, "plot_routines_low")
label(0xf6d8, "plot_routines_high")
for mode in range(5):
    code_ptr(0xf6d3 + mode, 0xf6d8 + mode, label_name="plot_mode_%d" % mode)
label(0xf6dd, "graphics_mode_bytes")
byte(0xf6dd, 5)
label(0xf7c9, "bit_masks")
byte(0xf7c9, 8)

# The assembler's tables (for BASIC's [ ... ])
for addr, length, name in ((0xf155, 64, "assembler_mnemonics_high"), (0xf195, 64, "assembler_mnemonics_low"),
                           (0xf1d5, 15, "assembler_mode_masks_low"), (0xf1e4, 15, "assembler_mode_masks_high"),
                           (0xf1f3, 15, "assembler_mode_offsets"), (0xf202, 15, "assembler_mode_offsets_2"),
                           (0xf211, 64, "assembler_mode_base_opcodes"), (0xf251, 64, "assembler_base_opcodes")):
    label(addr, name)
    byte(addr, length)

# OSWRCH's control codes, and OSRDCH's keys, with their handlers (whose
# addresses' low bytes are in a table, with the high byte #FD): the handler
# for each code (or key) from the one in the table up to the next
label(0xfecb, "wrch_control_codes")
byte(0xfecb, 11)
label(0xfed6, "rdch_keys")
byte(0xfed6, 13)
label(0xfee3, "wrch_control_code_handlers")
low_byte_table(0xfee3, 0xfd, ["wrch_invert_cursor", "wrch_backspace", "wrch_forward_space", "wrch_line_feed",
                              "wrch_up", "wrch_clear_screen", "wrch_return", "wrch_page_mode_on",
                              "wrch_page_mode_off", "wrch_home", "wrch_delete"])
label(0xfeee, "rdch_key_handlers")
low_byte_table(0xfeee, 0xfd, ["rdch_space_or_zero", "rdch_keys_1_to_4", "rdch_lock", "rdch_cursor",
                              "rdch_keys_8_to_13", "rdch_copy", "rdch_delete", "rdch_space_or_zero",
                              "rdch_digits", "rdch_keys_28_to_31", "rdch_at", "rdch_letters", "rdch_keys_59_to_63"])

go()
