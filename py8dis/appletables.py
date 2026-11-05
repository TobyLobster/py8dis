"""
Apple II tables

The data apple.py uses for the Apple II+ and IIe: the Monitor ROM's
routines, the Monitor's zero page and the other workspace, the page 3
vectors, the soft switches and the regions of memory.

Each name is given twice: Apple's (from Apple's reference manuals: the
Apple II Reference Manual's Monitor listing, and the Apple IIe Technical
Reference Manual), which apple.apple2() uses by default, in capitals; and a
descriptive one, for names="descriptive". The entries were checked against
the symbol files in Andy McFadden's 6502bench SourceGen (Apache 2.0), which
draw on "What's Where in the Apple" and NiftyList; no text is copied from
them.

Apple's names for the IIe's write-only switches at $C000-$C00F, such as
80STOREOFF, start with a digit in the newer manuals, so the older ones'
style is used (CLR80STORE, SET80STORE).
"""

# The Monitor's routines (at the same addresses in the II+'s Autostart ROM
# and the IIe's): (address, Apple's name, descriptive name, title, on_entry,
# on_exit). The title comments each call. on_entry and on_exit describe the
# registers (see subroutine()); apple.py adds hooks for those whose calls
# can say more when a register's value is known (see apple._HOOKS).
apple2_monitor_routines = [
    (0xf800, "PLOT",     "plot_lores_block",          "Plot a lo-res block (in COLOR)",                 {'a': "row (0-47)", 'y': "column (0-39)"}, None),
    (0xf80e, "PLOT1",    "plot_lores_block_in_row",   "Plot a lo-res block in the row GBASCALC set",    {'y': "column (0-39)"}, None),
    (0xf819, "HLINE",    "draw_lores_hline",          "Draw a lo-res horizontal line, to column H2",    {'a': "row", 'y': "left column"}, None),
    (0xf828, "VLINE",    "draw_lores_vline",          "Draw a lo-res vertical line, to row V2",         {'a': "top row", 'y': "column"}, None),
    (0xf832, "CLRSCR",   "clear_lores_screen",        "Clear the lo-res screen (all 48 rows)",          None, None),
    (0xf836, "CLRTOP",   "clear_lores_top",           "Clear the top 40 rows of the lo-res screen",     None, None),
    (0xf847, "GBASCALC", "calc_lores_row_address",    "Work out a lo-res row's address (in GBASL/GBASH)", {'a': "row"}, None),
    (0xf85f, "NXTCOL",   "next_lores_colour",         "Add 3 to the lo-res colour",                     None, None),
    (0xf864, "SETCOL",   "set_lores_colour",          "Set the lo-res colour",                          {'a': "colour (0-15)"}, None),
    (0xf871, "SCRN",     "read_lores_block",          "Read a lo-res block's colour",                   {'a': "row", 'y': "column"}, {'a': "colour"}),
    (0xf8d0, "INSTDSP",  "disassemble_instruction",   "Disassemble the instruction at PCL/PCH",         None, None),
    (0xf940, "PRNTYX",   "print_yx_hex",              "Print Y and X in hex",                           None, None),
    (0xf941, "PRNTAX",   "print_ax_hex",              "Print A and X in hex",                           None, None),
    (0xf944, "PRNTX",    "print_x_hex",               "Print X in hex",                                 None, None),
    (0xf948, "PRBLNK",   "print_3_spaces",            "Print 3 spaces",                                 None, None),
    (0xf94a, "PRBL2",    "print_spaces",              "Print spaces",                                   {'x': "number of spaces"}, None),
    (0xfa62, "RESET",    "reset",                     "The reset handler",                              None, None),
    (0xfad7, "REGDSP",   "print_registers",           "Print the registers saved at $45-$49",           None, None),
    (0xfb1e, "PREAD",    "read_paddle",               "Read a paddle",                                  {'x': "paddle (0-3)"}, {'y': "paddle's value (0-255)"}),
    (0xfb2f, "INIT",     "init_text_screen",          "Set text mode, page 1 and the full window",      None, None),
    (0xfb39, "SETTXT",   "set_text_mode",             "Set text mode, with the full window",            None, None),
    (0xfb40, "SETGR",    "set_lores_mode",            "Set lo-res mixed mode, and clear the graphics",  None, None),
    (0xfb4b, "SETWND",   "set_window",                "Set the text window to the full width, from row A down", {'a': "top row"}, None),
    (0xfb5b, "TABV",     "move_cursor_to_row",        "Move the cursor to a row",                       {'a': "row (0-23)"}, None),
    (0xfb60, "APPLEII",  "clear_screen_show_title",   "Clear the screen and show the machine's name",   None, None),
    (0xfb6f, "SETPWRC",  "set_power_up_byte",         "Set PWREDUP to match SOFTEV, so that reset uses it", None, None),
    (0xfbc1, "BASCALC",  "calc_text_row_address",     "Work out a text row's address (in BASL/BASH)",   {'a': "row"}, None),
    (0xfbdd, "BELL1",    "beep",                      "Beep the speaker",                               None, None),
    (0xfbf4, "ADVANCE",  "cursor_right",              "Move the cursor right",                          None, None),
    (0xfbfd, "VIDOUT",   "print_to_screen",           "Print a character on the screen",                {'a': "character"}, None),
    (0xfc10, "BS",       "cursor_left",               "Move the cursor left",                           None, None),
    (0xfc1a, "UP",       "cursor_up",                 "Move the cursor up",                             None, None),
    (0xfc22, "VTAB",     "move_cursor_to_cv",         "Move the cursor to row CV",                      None, None),
    (0xfc24, "VTABZ",    "move_cursor_to_row_a",      "Move the cursor to a row",                       {'a': "row (0-23)"}, None),
    (0xfc42, "CLREOP",   "clear_to_end_of_window",    "Clear from the cursor to the end of the window", None, None),
    (0xfc58, "HOME",     "clear_screen",              "Clear the window and put the cursor at its top left", None, None),
    (0xfc62, "CR",       "carriage_return",           "Move the cursor to the start of the next line",  None, None),
    (0xfc66, "LF",       "line_feed",                 "Move the cursor down a line",                    None, None),
    (0xfc70, "SCROLL",   "scroll_window",             "Scroll the window up a line",                    None, None),
    (0xfc9c, "CLREOL",   "clear_to_end_of_line",      "Clear from the cursor to the end of the line",   None, None),
    (0xfc9e, "CLREOLZ",  "clear_line_from_column",    "Clear the line from a column to its end",        {'y': "column"}, None),
    (0xfca8, "WAIT",     "wait",                      "Wait",                                           {'a': "delay"}, None),
    (0xfcb4, "NXTA4",    "next_a4_a1",                "Add 1 to A4 and A1",                             None, None),
    (0xfcba, "NXTA1",    "next_a1",                   "Add 1 to A1 (carry set if A1 was A2 or more)",   None, None),
    (0xfd0c, "RDKEY",    "read_key",                  "Read a key (through KSW)",                       None, {'a': "key (with bit 7 set)"}),
    (0xfd1b, "KEYIN",    "read_keyboard",             "Read a key from the keyboard",                   None, {'a': "key (with bit 7 set)"}),
    (0xfd35, "RDCHAR",   "read_char",                 "Read a key, acting on escape sequences",         None, {'a': "key (with bit 7 set)"}),
    (0xfd67, "GETLNZ",   "input_line_after_cr",       "Start a new line, then input a line into IN",    None, {'x': "line's length"}),
    (0xfd6a, "GETLN",    "input_line",                "Input a line into IN, after PROMPT",             None, {'x': "line's length"}),
    (0xfd6f, "GETLN1",   "input_line_no_prompt",      "Input a line into IN, without a prompt",         None, {'x': "line's length"}),
    (0xfd8b, "CROUT1",   "clear_eol_print_cr",        "Clear to the end of the line, then start a new line", None, None),
    (0xfd8e, "CROUT",    "print_cr",                  "Start a new line",                               None, None),
    (0xfd92, "PRA1",     "print_a1",                  "Start a new line, then print A1 in hex and '-'", None, None),
    (0xfdda, "PRBYTE",   "print_hex_byte",            "Print A in hex",                                 None, None),
    (0xfde3, "PRHEX",    "print_hex_digit",           "Print A's low 4 bits in hex",                    None, None),
    (0xfded, "COUT",     "print_char",                "Print a character (through CSW)",                {'a': "character"}, None),
    (0xfdf0, "COUT1",    "print_char_to_screen",      "Print a character on the screen",                {'a': "character"}, None),
    (0xfe2c, "MOVE",     "move_memory",               "Copy A1 to A2 to A4 (with Y=0)",                 None, None),
    (0xfe36, "VFY",      "verify_memory",             "Compare A1 to A2 with A4 (with Y=0)",            None, None),
    (0xfe5e, "LIST",     "disassemble_20",            "Disassemble 20 instructions",                    None, None),
    (0xfe80, "SETINV",   "set_inverse",               "Print in inverse",                               None, None),
    (0xfe84, "SETNORM",  "set_normal",                "Print in normal text",                           None, None),
    (0xfe89, "SETKBD",   "input_from_keyboard",       "Take input from the keyboard (IN#0)",            None, None),
    (0xfe8b, "INPORT",   "input_from_slot",           "Take input from a slot (IN#)",                   {'a': "slot"}, None),
    (0xfe93, "SETVID",   "output_to_screen",          "Send output to the screen (PR#0)",               None, None),
    (0xfe95, "OUTPORT",  "output_to_slot",            "Send output to a slot (PR#)",                    {'a': "slot"}, None),
    (0xfecd, "WRITE",    "write_tape",                "Write A1 to A2 to tape",                         None, None),
    (0xfefd, "READ",     "read_tape",                 "Read tape into A1 to A2",                        None, None),
    (0xff2d, "PRERR",    "print_err",                 "Print \"ERR\" and beep",                         None, None),
    (0xff3a, "BELL",     "bell",                      "Beep (by printing Ctrl-G)",                      None, None),
    (0xff3f, "RESTORE",  "restore_registers",         "Restore A, X, Y and P from $45-$48",             None, None),
    (0xff4a, "SAVE",     "save_registers",            "Save A, X, Y, P and S to $45-$49",               None, None),
    (0xff58, "IORTS",    "known_rts",                 "Return (an RTS: code calls it to find its own address on the stack)", None, None),
    (0xff59, "OLDRST",   "monitor_reset",             "Enter the Monitor, resetting the I/O and screen", None, None),
    (0xff65, "MON",      "monitor",                   "Enter the Monitor with a beep",                  None, None),
    (0xff69, "MONZ",     "monitor_no_beep",           "Enter the Monitor",                              None, None),
]

# The IIe's firmware routines in its slot 3 ROM (the 80-column firmware,
# from $C300): (address, Apple's name, descriptive name, title, on_entry,
# on_exit), as for the Monitor's.
apple2e_firmware_routines = [
    (0xc311, "AUXMOVE",  "aux_move",                  "Copy A1 to A2 to A4 in the other memory (C set: main to auxiliary)", None, None),
    (0xc314, "XFER",     "aux_transfer",              "Jump to the address at $03ED in the other memory (C set: to auxiliary; V set: auxiliary zero page)", None, None),
]

# Other places in the Monitor ROM: (address, Apple's name, descriptive name)
apple2_rom_locations = [
    (0xfbb3, "VERSION",  "rom_id_byte"),
    (0xfbc0, "ZIDBYTE",  "rom_id_byte_2"),
]

# The Monitor's zero page and the other workspace: (address, Apple's name,
# descriptive name, length). A descriptive name with a length over 1 names
# the other bytes as e.g. 'text_line_address+1'; Apple's names often name
# each byte (BASL, BASH), so those are separate entries, with length 1.
apple2_workspace = [
    (0x20, "WNDLFT",   "window_left",         1),
    (0x21, "WNDWDTH",  "window_width",        1),
    (0x22, "WNDTOP",   "window_top",          1),
    (0x23, "WNDBTM",   "window_bottom",       1),
    (0x24, "CH",       "cursor_column",       1),
    (0x25, "CV",       "cursor_row",          1),
    (0x26, "GBASL",    "lores_row_address",   2),
    (0x28, "BASL",     "text_row_address",    2),
    (0x2a, "BAS2L",    "scroll_row_address",  2),
    (0x2c, "H2",       "line_end_column",     1),
    (0x2d, "V2",       "line_end_row",        1),
    (0x2e, "MASK",     "lores_mask",          1),
    (0x30, "COLOR",    "lores_colour",        1),
    (0x31, "MODE",     "monitor_mode",        1),
    (0x32, "INVFLG",   "text_mask",           1),
    (0x33, "PROMPT",   "prompt_char",         1),
    (0x34, "YSAV",     "monitor_y_save",      1),
    (0x35, "YSAV1",    "monitor_y_save_2",    1),
    (0x36, "CSWL",     "output_hook",         2),
    (0x38, "KSWL",     "input_hook",          2),
    (0x3a, "PCL",      "monitor_pc",          2),
    (0x3c, "A1L",      "monitor_a1",          2),
    (0x3e, "A2L",      "monitor_a2",          2),
    (0x40, "A3L",      "monitor_a3",          2),
    (0x42, "A4L",      "monitor_a4",          2),
    (0x44, "A5L",      "monitor_a5",          1),
    (0x45, "ACC",      "saved_a",             1),
    (0x46, "XREG",     "saved_x",             1),
    (0x47, "YREG",     "saved_y",             1),
    (0x48, "STATUS",   "saved_p",             1),
    (0x49, "SPNT",     "saved_s",             1),
    (0x4e, "RNDL",     "random",              2),
    (0x0200, "IN",     "input_buffer",        256),
]

# Apple's names for the high bytes of the two-byte locations above, which
# name them separately (the descriptive names are e.g. 'output_hook+1')
apple2_workspace_high_bytes = {
    0x27: "GBASH",
    0x29: "BASH",
    0x2b: "BAS2H",
    0x37: "CSWH",
    0x39: "KSWH",
    0x3b: "PCH",
    0x3d: "A1H",
    0x3f: "A2H",
    0x41: "A3H",
    0x43: "A4H",
    0x4f: "RNDH",
}

# The page 3 vectors: (address, Apple's name, descriptive name, length). The
# BRK, reset and IRQ vectors are addresses; the others are JMP instructions,
# whose address is the 2 bytes after the opcode.
apple2_page3_vectors = [
    (0x03f0, "BRKV",    "brk_vector",        2),
    (0x03f2, "SOFTEV",  "reset_vector",      2),
    (0x03f4, "PWREDUP", "power_up_byte",     1),
    (0x03f5, "AMPERV",  "ampersand_jump",    3),
    (0x03f8, "USRADR",  "ctrl_y_jump",       3),
    (0x03fb, "NMI",     "nmi_jump",          3),
    (0x03fe, "IRQLOC",  "irq_vector",        2),
]

# The vectors that code sets to its own handlers, for the effect pattern
# that traces and names them (see apple.py): the address of the vector's
# two bytes, then the name its handler is given (e.g. 'reset_handler') and
# what it is, for the comment (e.g. "Set the reset vector to
# 'reset_handler'")
apple2_vectors = {
    0x0036: ("output_handler",    "the output hook (CSW)"),
    0x0038: ("input_handler",     "the input hook (KSW)"),
    0x03f0: ("brk_handler",       "the BRK vector"),
    0x03f2: ("reset_handler",     "the reset vector"),
    0x03f6: ("ampersand_handler", "the & command's JMP"),
    0x03f9: ("ctrl_y_handler",    "the Monitor's Ctrl-Y JMP"),
    0x03fc: ("nmi_handler",       "the NMI JMP"),
    0x03fe: ("irq_handler",       "the IRQ vector"),
}

# What the Monitor's screen output (COUT1, through COUT) does with the
# control characters it acts on (with bit 7 set), for the comments on what
# code prints. Ctrl-D isn't one, but DOS takes it, after a CR, to start a
# command.
apple2_control_codes = {
    0x84: "Ctrl-D (to start a DOS command)",
    0x87: "a beep",
    0x88: "a backspace",
    0x8a: "a line feed",
    0x8d: "a carriage return",
}

# The soft switches and other I/O, as read (or accessed either way), on all
# models: {address: (Apple's name, descriptive name)}. The IIe's are in
# apple2e_soft_switches.
apple2_soft_switches = {
    0xc000: ("KBD",      "keyboard"),
    0xc010: ("KBDSTRB",  "keyboard_strobe"),
    0xc020: ("TAPEOUT",  "tape_out"),
    0xc030: ("SPKR",     "speaker"),
    0xc040: ("STROBE",   "game_strobe"),
    0xc050: ("TXTCLR",   "show_graphics"),
    0xc051: ("TXTSET",   "show_text"),
    0xc052: ("MIXCLR",   "full_screen"),
    0xc053: ("MIXSET",   "mixed_screen"),
    0xc054: ("TXTPAGE1", "show_page_1"),
    0xc055: ("TXTPAGE2", "show_page_2"),
    0xc056: ("LORES",    "show_lores"),
    0xc057: ("HIRES",    "show_hires"),
    0xc058: ("CLRAN0",   "annunciator_0_off"),
    0xc059: ("SETAN0",   "annunciator_0_on"),
    0xc05a: ("CLRAN1",   "annunciator_1_off"),
    0xc05b: ("SETAN1",   "annunciator_1_on"),
    0xc05c: ("CLRAN2",   "annunciator_2_off"),
    0xc05d: ("SETAN2",   "annunciator_2_on"),
    0xc05e: ("CLRAN3",   "annunciator_3_off"),
    0xc05f: ("SETAN3",   "annunciator_3_on"),
    0xc060: ("TAPEIN",   "tape_in"),
    0xc061: ("BUTN0",    "button_0"),
    0xc062: ("BUTN1",    "button_1"),
    0xc063: ("BUTN2",    "button_2"),
    0xc064: ("PADDL0",   "paddle_0"),
    0xc065: ("PADDL1",   "paddle_1"),
    0xc066: ("PADDL2",   "paddle_2"),
    0xc067: ("PADDL3",   "paddle_3"),
    0xc070: ("PTRIG",    "paddle_trigger"),
    0xcfff: ("CLRROM",   "release_expansion_rom"),
}

# The IIe's status switches, read with bit 7 the state: {address: (Apple's
# name, descriptive name)}
apple2e_soft_switches = {
    0xc011: ("RDLCBNK2",  "is_lc_bank_2"),
    0xc012: ("RDLCRAM",   "is_lc_ram"),
    0xc013: ("RDRAMRD",   "is_reading_aux"),
    0xc014: ("RDRAMWRT",  "is_writing_aux"),
    0xc015: ("RDCXROM",   "is_internal_cx_rom"),
    0xc016: ("RDALTZP",   "is_aux_zero_page"),
    0xc017: ("RDC3ROM",   "is_slot_c3_rom"),
    0xc018: ("RD80STORE", "is_80store"),
    0xc019: ("RDVBLBAR",  "is_not_vertical_blank"),
    0xc01a: ("RDTEXT",    "is_text"),
    0xc01b: ("RDMIXED",   "is_mixed"),
    0xc01c: ("RDPAGE2",   "is_page_2"),
    0xc01d: ("RDHIRES",   "is_hires"),
    0xc01e: ("RDALTCHAR", "is_alt_charset"),
    0xc01f: ("RD80VID",   "is_80_columns"),
}

# The language card's switches (all models), as accessed without an index:
# {address: (Apple's name, descriptive name)}. Where Apple's documentation
# has no name (only ROMIN, LCBANK2 and LCBANK1 are well known, as in cc65's
# apple2.inc), it's None, and the descriptive name is used in both styles. $C084-$C087 and
# $C08C-$C08F act as $C080-$C083 and $C088-$C08B, and aren't named.
apple2_language_card = {
    0xc080: (None,      "lc_read_ram_2"),
    0xc081: ("ROMIN",   "lc_read_rom_write_ram_2"),
    0xc082: (None,      "lc_read_rom"),
    0xc083: ("LCBANK2", "lc_read_write_ram_2"),
    0xc088: (None,      "lc_read_ram_1"),
    0xc089: (None,      "lc_read_rom_write_ram_1"),
    0xc08a: (None,      "lc_read_rom_1"),
    0xc08b: ("LCBANK1", "lc_read_write_ram_1"),
}

# What accessing each of the language card's switches does (the low 3 bits
# of the address, and bit 3 for the bank), for the comments: reading one of
# the odd ones twice in a row enables writing to the RAM
def apple2_language_card_action(addr):
    """What accessing the language card's switch at addr ($C080-$C08F)
    does, e.g. 'Language card: read ROM, write RAM bank 2 (two reads enable
    writing)'."""
    bank = 1 if addr & 0x08 else 2
    return "Language card: " + [
        "read RAM bank {0}, no writing",
        "read ROM, write RAM bank {0} (two reads in a row enable writing)",
        "read ROM, no writing",
        "read and write RAM bank {0} (two reads in a row enable writing)"][addr & 0x03].format(bank)

# What accessing each soft switch does, read or written (the 6502's STA
# without an index writes once, so it's the same as a read), for the
# comments: {address: text}
apple2_switch_actions = {
    0xc010: "Clear the keyboard strobe",
    0xc020: "Toggle the tape output",
    0xc030: "Click the speaker",
    0xc040: "Pulse the game I/O strobe",
    0xc050: "Show graphics",
    0xc051: "Show text",
    0xc052: "Show graphics on the full screen",
    0xc053: "Show text on the bottom 4 lines (mixed mode)",
    0xc054: "Show page 1",
    0xc055: "Show page 2",
    0xc056: "Show lo-res graphics",
    0xc057: "Show hi-res graphics",
    0xc058: "Turn annunciator 0 off",
    0xc059: "Turn annunciator 0 on",
    0xc05a: "Turn annunciator 1 off",
    0xc05b: "Turn annunciator 1 on",
    0xc05c: "Turn annunciator 2 off",
    0xc05d: "Turn annunciator 2 on",
    0xc05e: "Turn annunciator 3 off",
    0xc05f: "Turn annunciator 3 on",
    0xc070: "Start the paddles' timers",
    0xcfff: "Release the expansion ROM ($C800-$CFFF)",
}

# What reading each input tests, in bit 7, for the comments: {address:
# text}. The comment is 'Test ' and the text, e.g. 'Test button 0 (bit 7
# set if it's pressed)'.
apple2_inputs = {
    0xc000: "for a key (bit 7 set if one has been pressed)",
    0xc060: "the tape input (bit 7)",
    0xc061: "button 0 (bit 7 set if it's pressed)",
    0xc062: "button 1 (bit 7 set if it's pressed)",
    0xc063: "button 2 (bit 7 set if it's pressed)",
    0xc064: "paddle 0's timer (bit 7 set until it runs out)",
    0xc065: "paddle 1's timer (bit 7 set until it runs out)",
    0xc066: "paddle 2's timer (bit 7 set until it runs out)",
    0xc067: "paddle 3's timer (bit 7 set until it runs out)",
}

# The IIe's: its buttons 0 and 1 are the Open Apple and Solid Apple keys,
# and its status switches
apple2e_inputs = {
    0xc061: "the Open Apple key (bit 7 set if it's pressed)",
    0xc062: "the Solid Apple key (bit 7 set if it's pressed)",
    0xc011: "whether the language card's bank 2 is selected (bit 7)",
    0xc012: "whether the language card's RAM is being read (bit 7)",
    0xc013: "whether auxiliary memory is being read (bit 7)",
    0xc014: "whether auxiliary memory is being written (bit 7)",
    0xc015: "whether the internal $C100-$CFFF ROM is selected (bit 7)",
    0xc016: "whether the auxiliary zero page and stack are selected (bit 7)",
    0xc017: "whether slot 3's ROM is selected (bit 7)",
    0xc018: "whether 80STORE is on (bit 7)",
    0xc019: "for the vertical blank (bit 7 clear during it)",
    0xc01a: "whether text is shown (bit 7)",
    0xc01b: "whether mixed mode is on (bit 7)",
    0xc01c: "whether page 2 is shown (bit 7)",
    0xc01d: "whether hi-res is shown (bit 7)",
    0xc01e: "whether the alternate character set is selected (bit 7)",
    0xc01f: "whether 80 columns are shown (bit 7)",
}

# The IIe's switches at $C000-$C00F, which act when written (reading them
# reads the keyboard): {address: (Apple's name, descriptive name, what it
# does)}. They're named only where they're written (see apple.py).
apple2e_write_switches = {
    0xc000: ("CLR80STORE",   "store_80_off",       "Use RAMRD and RAMWRT for auxiliary memory (80STORE off)"),
    0xc001: ("SET80STORE",   "store_80_on",        "Use page 2 for auxiliary memory (80STORE on)"),
    0xc002: ("RDMAINRAM",    "read_main_ram",      "Read main memory ($0200-$BFFF)"),
    0xc003: ("RDCARDRAM",    "read_aux_ram",       "Read auxiliary memory ($0200-$BFFF)"),
    0xc004: ("WRMAINRAM",    "write_main_ram",     "Write main memory ($0200-$BFFF)"),
    0xc005: ("WRCARDRAM",    "write_aux_ram",      "Write auxiliary memory ($0200-$BFFF)"),
    0xc006: ("SETSLOTCXROM", "slot_cx_rom",        "Use the slots' ROMs at $C100-$CFFF"),
    0xc007: ("SETINTCXROM",  "internal_cx_rom",    "Use the internal ROM at $C100-$CFFF"),
    0xc008: ("SETSTDZP",     "main_zero_page",     "Use the main zero page, stack and language card"),
    0xc009: ("SETALTZP",     "aux_zero_page",      "Use the auxiliary zero page, stack and language card"),
    0xc00a: ("SETINTC3ROM",  "internal_c3_rom",    "Use the internal ROM at $C300"),
    0xc00b: ("SETSLOTC3ROM", "slot_c3_rom",        "Use slot 3's ROM at $C300"),
    0xc00c: ("CLR80VID",     "show_40_columns",    "Show 40 columns"),
    0xc00d: ("SET80VID",     "show_80_columns",    "Show 80 columns"),
    0xc00e: ("CLRALTCHAR",   "primary_charset",    "Use the primary character set"),
    0xc00f: ("SETALTCHAR",   "alt_charset",        "Use the alternate character set (with MouseText)"),
}

# The Disk II controller's switches, used with the slot times 16 as the index
# (e.g. 'lda Q6L,x' with X=$60 for slot 6), as in DOS 3.3's RWTS: {offset:
# (Apple's name, descriptive name, what it does)}. The stepper's phases 1-3
# are at offsets 2-7, which RWTS reaches by adding the phase times 2 to X.
apple2_disk2_switches = {
    0x0: ("PHASEOFF",  "disk_phase_off",   "Disk II: turn a stepper phase off"),
    0x1: ("PHASEON",   "disk_phase_on",    "Disk II: turn a stepper phase on"),
    0x2: ("PHASE1OFF", "disk_phase_1_off", "Disk II: turn the stepper's phase 1 off"),
    0x3: ("PHASE1ON",  "disk_phase_1_on",  "Disk II: turn the stepper's phase 1 on"),
    0x4: ("PHASE2OFF", "disk_phase_2_off", "Disk II: turn the stepper's phase 2 off"),
    0x5: ("PHASE2ON",  "disk_phase_2_on",  "Disk II: turn the stepper's phase 2 on"),
    0x6: ("PHASE3OFF", "disk_phase_3_off", "Disk II: turn the stepper's phase 3 off"),
    0x7: ("PHASE3ON",  "disk_phase_3_on",  "Disk II: turn the stepper's phase 3 on"),
    0x8: ("MOTOROFF",  "disk_motor_off",   "Disk II: turn the motor off"),
    0x9: ("MOTORON",   "disk_motor_on",    "Disk II: turn the motor on"),
    0xa: ("DRV0EN",    "disk_drive_1",     "Disk II: select drive 1"),
    0xb: ("DRV1EN",    "disk_drive_2",     "Disk II: select drive 2"),
    0xc: ("Q6L",       "disk_q6_low",      "Disk II: Q6 low (read the data latch)"),
    0xd: ("Q6H",       "disk_q6_high",     "Disk II: Q6 high (sense write protect, or load the data latch)"),
    0xe: ("Q7L",       "disk_q7_low",      "Disk II: Q7 low (read mode)"),
    0xf: ("Q7H",       "disk_q7_high",     "Disk II: Q7 high (write mode)"),
}

# The heading for the Disk II's names in the list of memory locations
APPLE2_DISK2_HEADING = "Disk II (indexed by the slot times 16)"

# The lo-res colours, for the comments on SETCOL
apple2_lores_colours = ["black", "magenta", "dark blue", "purple", "dark green", "grey", "medium blue", "light blue",
                        "brown", "orange", "grey", "pink", "green", "yellow", "aquamarine", "white"]

# The regions of memory, to group the list of memory locations at the top of
# the output: (start, end, name), 'end' exclusive
apple2_memory_regions = [
    (0x0000, 0x0100, "Zero page"),
    (0x0100, 0x0200, "Stack"),
    (0x0200, 0x0300, "Input buffer"),
    (0x0300, 0x03d0, "Page 3"),
    (0x03d0, 0x03f0, "DOS vectors"),
    (0x03f0, 0x0400, "Vectors"),
    (0x0400, 0x0800, "Text and lo-res page 1"),
    (0x0800, 0x0c00, "Text and lo-res page 2"),
    (0x2000, 0x4000, "Hi-res page 1"),
    (0x4000, 0x6000, "Hi-res page 2"),
    (0xc000, 0xc080, "Soft switches"),
    (0xc080, 0xc090, "Language card"),
    (0xc090, 0xc100, "Slot I/O"),
    (0xc100, 0xc800, "Slot ROMs"),
    (0xc800, 0xd000, "Expansion ROM"),
    (0xd000, 0xf800, "Applesoft ROM"),
    (0xf800, 0x10000, "Monitor ROM"),
]
