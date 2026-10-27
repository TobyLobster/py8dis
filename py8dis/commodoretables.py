"""
The Commodore machines' data tables, for commodore.py: names for the memory
locations, hardware registers and Kernal calls, the Kernal's control codes,
the colours, the device numbers and the BASIC tokens.

Each memory location has two names: a descriptive one (the default, e.g.
'vic_border_colour') and the one Commodore's documentation uses (from the
Commodore 64 Programmer's Reference Guide and Commodore's own source, or for
the I/O registers from "Mapping the Commodore 64", e.g. 'extcol'), chosen with
commodore.c64(names=...). The Kernal calls have Commodore's names (e.g.
'chrout') either way.

The names, addresses and Kernal calling conventions are from Michael Steil's
c64ref (https://github.com/mist64/c64ref, (c) 2022 Michael Steil; its BSD
2-clause licence is in commodoreromlabels.py): src/c64mem/symbols.txt,
src/c64io, src/kernal and src/charset.
"""

from collections import namedtuple

# A memory location: its address, its size in bytes (a name is given to each
# byte, e.g. 'tape_buffer+1'), Commodore's name (None if it has none, in which
# case the descriptive name is used) and the descriptive name.
Location = namedtuple("Location", ["addr", "size", "commodore_name", "name"])

# ************************************************************************************************
# C64 RAM: zero page, the OS and BASIC workspace, the vectors and the screen

c64_ram_locations = [
    # The 6510's I/O port
    Location(0x0000, 1, "d6510",  "cpu_port_direction"),
    Location(0x0001, 1, "r6510",  "cpu_port"),

    # BASIC's zero page
    Location(0x0003, 2, "adray1", "basic_float_to_int_vector"),
    Location(0x0005, 2, "adray2", "basic_int_to_float_vector"),
    Location(0x0007, 1, "charac", "basic_search_char"),
    Location(0x0008, 1, "endchr", "basic_end_char"),
    Location(0x0009, 1, "trmpos", "basic_tab_column"),
    Location(0x000a, 1, "verckb", "basic_load_verify_flag"),
    Location(0x000b, 1, "count",  "basic_input_buffer_index"),
    Location(0x000c, 1, "dimflg", "basic_dim_flag"),
    Location(0x000d, 1, "valtyp", "basic_value_type"),
    Location(0x000e, 1, "intflg", "basic_integer_flag"),
    Location(0x000f, 1, "garbfl", "basic_garbage_flag"),
    Location(0x0010, 1, "subflg", "basic_subscript_flag"),
    Location(0x0011, 1, "inpflg", "basic_input_flag"),
    Location(0x0012, 1, "tansgn", "basic_tan_sign"),
    Location(0x0013, 1, "channl", "basic_current_channel"),
    Location(0x0014, 2, "linnum", "basic_line_number"),
    Location(0x0016, 1, "temppt", "basic_temp_string_index"),
    Location(0x0017, 2, "lastpt", "basic_last_temp_string"),
    Location(0x0019, 9, "tempst", "basic_temp_string_stack"),
    Location(0x0022, 2, "index1", "basic_index1"),
    Location(0x0024, 2, "index2", "basic_index2"),
    Location(0x0026, 5, "resho",  "basic_multiply_result"),
    Location(0x002b, 2, "txttab", "basic_program_start"),
    Location(0x002d, 2, "vartab", "basic_variables_start"),
    Location(0x002f, 2, "arytab", "basic_arrays_start"),
    Location(0x0031, 2, "strend", "basic_arrays_end"),
    Location(0x0033, 2, "fretop", "basic_strings_bottom"),
    Location(0x0035, 2, "frespc", "basic_string_temp_ptr"),
    Location(0x0037, 2, "memsiz", "basic_memory_top"),
    Location(0x0039, 2, "curlin", "basic_current_line"),
    Location(0x003b, 2, "oldlin", "basic_previous_line"),
    Location(0x003d, 2, "oldtxt", "basic_statement_ptr"),
    Location(0x003f, 2, "datlin", "basic_data_line"),
    Location(0x0041, 2, "datptr", "basic_data_ptr"),
    Location(0x0043, 2, "inpptr", "basic_input_ptr"),
    Location(0x0045, 2, "varnam", "basic_variable_name"),
    Location(0x0047, 2, "varpnt", "basic_variable_ptr"),
    Location(0x0049, 2, "forpnt", "basic_for_variable_ptr"),
    Location(0x004b, 2, "opptr",  "basic_operator_ptr"),
    Location(0x004d, 1, "opmask", "basic_comparison_mask"),
    Location(0x004e, 2, "defpnt", "basic_fn_ptr"),
    Location(0x0050, 3, "dscpnt", "basic_string_descriptor_ptr"),
    Location(0x0053, 1, "four6",  "basic_garbage_step"),
    Location(0x0054, 3, "jmper",  "basic_function_jump"),
    Location(0x0057, 5, "tempf1", "basic_float_temp1"),
    Location(0x005c, 5, "tempf2", "basic_float_temp2"),
    Location(0x0061, 1, "facexp", "fac1_exponent"),
    Location(0x0062, 4, "facho",  "fac1_mantissa"),
    Location(0x0066, 1, "facsgn", "fac1_sign"),
    Location(0x0067, 1, "sgnflg", "basic_series_terms"),
    Location(0x0068, 1, "bits",   "fac1_overflow"),
    Location(0x0069, 1, "argexp", "fac2_exponent"),
    Location(0x006a, 4, "argho",  "fac2_mantissa"),
    Location(0x006e, 1, "argsgn", "fac2_sign"),
    Location(0x006f, 1, "arisgn", "fac_compare_sign"),
    Location(0x0070, 1, "facov",  "fac1_rounding"),
    Location(0x0071, 2, "fbufpt", "basic_series_ptr"),
    Location(0x0073, 6, "chrget", "basic_chrget"),
    Location(0x0079, 1, "chrgot", "basic_chrgot"),
    Location(0x007a, 2, "txtptr", "basic_text_ptr"),
    Location(0x008b, 5, "rndx",   "basic_rnd_seed"),

    # The Kernal's zero page
    Location(0x0090, 1, "status", "io_status"),
    Location(0x0091, 1, "stkey",  "stop_key_flag"),
    Location(0x0092, 1, "svxt",   "tape_timing"),
    Location(0x0093, 1, "verck",  "load_verify_flag"),
    Location(0x0094, 1, "c3p0",   "serial_char_buffered_flag"),
    Location(0x0095, 1, "bsour",  "serial_buffered_char"),
    Location(0x0096, 1, "syno",   "tape_sync_number"),
    Location(0x0097, 1, "xsav",   "kernal_x_save"),
    Location(0x0098, 1, "ldtnd",  "open_files_count"),
    Location(0x0099, 1, "dfltn",  "input_device"),
    Location(0x009a, 1, "dflto",  "output_device"),
    Location(0x009b, 1, "prty",   "tape_parity"),
    Location(0x009c, 1, "dpsw",   "tape_byte_received_flag"),
    Location(0x009d, 1, "msgflg", "kernal_message_flags"),
    Location(0x009e, 1, "ptr1",   "tape_pass1_errors"),
    Location(0x009f, 1, "ptr2",   "tape_pass2_errors"),
    Location(0x00a0, 3, "time",   "jiffy_clock"),
    Location(0x00a3, 1, "pcntr",  "io_temp_1"),
    Location(0x00a4, 1, "firt",   "io_temp_2"),
    Location(0x00a5, 1, "cntdn",  "tape_sync_countdown"),
    Location(0x00a6, 1, "bufpt",  "tape_buffer_index"),
    Location(0x00a7, 1, "inbit",  "rs232_input_bits"),
    Location(0x00a8, 1, "bitci",  "rs232_input_bit_count"),
    Location(0x00a9, 1, "rinone", "rs232_start_bit_flag"),
    Location(0x00aa, 1, "ridata", "rs232_input_byte"),
    Location(0x00ab, 1, "riprty", "rs232_input_parity"),
    Location(0x00ac, 2, "sal",    "io_address_ptr"),
    Location(0x00ae, 2, "eal",    "io_end_ptr"),
    Location(0x00b0, 2, "cmp0",   "tape_timing_constant"),
    Location(0x00b2, 2, "tape1",  "tape_buffer_ptr"),
    Location(0x00b4, 1, "bitts",  "rs232_output_bit_count"),
    Location(0x00b5, 1, "nxtbit", "rs232_next_bit"),
    Location(0x00b6, 1, "rodata", "rs232_output_byte"),
    Location(0x00b7, 1, "fnlen",  "filename_length"),
    Location(0x00b8, 1, "la",     "logical_file_number"),
    Location(0x00b9, 1, "sa",     "secondary_address"),
    Location(0x00ba, 1, "fa",     "device_number"),
    Location(0x00bb, 2, "fnadr",  "filename_ptr"),
    Location(0x00bd, 1, "roprty", "rs232_output_parity"),
    Location(0x00be, 1, "fsblk",  "tape_block_count"),
    Location(0x00bf, 1, "mych",   "tape_input_byte"),
    Location(0x00c0, 1, "cas1",   "tape_motor_interlock"),
    Location(0x00c1, 2, "stal",   "io_start_ptr"),
    Location(0x00c3, 2, "memuss", "load_address_temp"),
    Location(0x00c5, 1, "lstx",   "last_key_pressed"),
    Location(0x00c6, 1, "ndx",    "keyboard_buffer_length"),
    Location(0x00c7, 1, "rvs",    "reverse_flag"),
    Location(0x00c8, 1, "indx",   "input_line_end"),
    Location(0x00c9, 2, "lsxp",   "input_cursor_start"),
    Location(0x00cb, 1, "sfdx",   "current_key_pressed"),
    Location(0x00cc, 1, "blnsw",  "cursor_blink_disable"),
    Location(0x00cd, 1, "blnct",  "cursor_blink_timer"),
    Location(0x00ce, 1, "gdbln",  "char_under_cursor"),
    Location(0x00cf, 1, "blnon",  "cursor_blink_phase"),
    Location(0x00d0, 1, "crsw",   "input_from_screen_flag"),
    Location(0x00d1, 2, "pnt",    "screen_line_ptr"),
    Location(0x00d3, 1, "pntr",   "cursor_column"),
    Location(0x00d4, 1, "qtsw",   "quote_mode_flag"),
    Location(0x00d5, 1, "lnmx",   "screen_line_length"),
    Location(0x00d6, 1, "tblx",   "cursor_row"),
    Location(0x00d7, 1, "data",   "last_char_printed"),
    Location(0x00d8, 1, "insrt",  "insert_count"),
    Location(0x00d9, 26, "ldtb1", "screen_line_links"),
    Location(0x00f3, 2, "user",   "colour_ram_line_ptr"),
    Location(0x00f5, 2, "keytab", "keyboard_table_ptr"),
    Location(0x00f7, 2, "ribuf",  "rs232_input_buffer_ptr"),
    Location(0x00f9, 2, "robuf",  "rs232_output_buffer_ptr"),
    Location(0x00fb, 4, "frekzp", "free_zero_page"),
    Location(0x00ff, 1, "baszpt", "basic_float_to_ascii_temp"),

    # The OS and BASIC workspace
    Location(0x0200, 89, "buf",   "basic_input_buffer"),
    Location(0x0259, 10, "lat",   "logical_file_table"),
    Location(0x0263, 10, "fat",   "device_number_table"),
    Location(0x026d, 10, "sat",   "secondary_address_table"),
    Location(0x0277, 10, "keyd",  "keyboard_buffer"),
    Location(0x0281, 2, "memstr", "os_memory_start"),
    # (Commodore's name for this is MEMSIZ, as for BASIC's &0037, so
    # BASIC's has that name here)
    Location(0x0283, 2, "memsiz_kernal", "os_memory_end"),
    Location(0x0285, 1, "timout", "serial_timeout_flag"),
    Location(0x0286, 1, "color",  "text_colour"),
    Location(0x0287, 1, "gdcol",  "colour_under_cursor"),
    Location(0x0288, 1, "hibase", "screen_memory_page"),
    Location(0x0289, 1, "xmax",   "keyboard_buffer_size"),
    Location(0x028a, 1, "rptflg", "key_repeat_flags"),
    Location(0x028b, 1, "kount",  "key_repeat_counter"),
    Location(0x028c, 1, "delay",  "key_repeat_delay"),
    Location(0x028d, 1, "shflag", "shift_key_flags"),
    Location(0x028e, 1, "lstshf", "last_shift_key_flags"),
    Location(0x028f, 2, "keylog", "keyboard_table_setup_vector"),
    Location(0x0291, 1, "mode",   "charset_switch_flag"),
    Location(0x0292, 1, "autodn", "screen_scroll_flag"),
    Location(0x0293, 1, "m51ctr", "rs232_control"),
    Location(0x0294, 1, "m51cdr", "rs232_command"),
    Location(0x0295, 2, "m51ajb", "rs232_bit_timing"),
    Location(0x0297, 1, "rsstat", "rs232_status"),
    Location(0x0298, 1, "bitnum", "rs232_bits_left"),
    Location(0x0299, 2, "baudof", "rs232_bit_time"),
    Location(0x029b, 1, "ridbe",  "rs232_receive_end"),
    Location(0x029c, 1, "ridbs",  "rs232_receive_start"),
    Location(0x029d, 1, "rodbs",  "rs232_transmit_start"),
    Location(0x029e, 1, "rodbe",  "rs232_transmit_end"),
    Location(0x029f, 2, "irqtmp", "tape_irq_vector_save"),
    Location(0x02a1, 1, "enabl",  "rs232_interrupts"),
    Location(0x02a2, 1, "caston", "tape_cia1_control_b_save"),
    Location(0x02a3, 1, "kika26", "tape_cia1_interrupt_save"),
    Location(0x02a4, 1, "stupid", "tape_cia1_control_a_save"),
    Location(0x02a5, 1, "lintmp", "screen_scroll_line"),
    Location(0x02a6, 1, "palnts", "pal_ntsc_flag"),

    # BASIC's vectors and SYS's registers
    Location(0x0300, 2, "ierror", "basic_error_vector"),
    Location(0x0302, 2, "imain",  "basic_main_loop_vector"),
    Location(0x0304, 2, "icrnch", "basic_tokenise_vector"),
    Location(0x0306, 2, "iqplop", "basic_list_token_vector"),
    Location(0x0308, 2, "igone",  "basic_execute_vector"),
    Location(0x030a, 2, "ieval",  "basic_evaluate_vector"),
    Location(0x030c, 1, "sareg",  "sys_a"),
    Location(0x030d, 1, "sxreg",  "sys_x"),
    Location(0x030e, 1, "syreg",  "sys_y"),
    Location(0x030f, 1, "spreg",  "sys_p"),
    Location(0x0310, 1, "usrpok", "usr_jmp"),
    Location(0x0311, 2, "usradd", "usr_address"),
]

# The Kernal's vectors (in RAM), each with a description for comments, e.g.
# when a program sets the IRQ vector. (Those used for a snippet that sets a
# vector, along with BASIC's above.)
VectorLocation = namedtuple("VectorLocation", ["addr", "commodore_name", "name", "description", "handler"])

c64_vectors = [
    VectorLocation(0x0314, "cinv",   "irq_vector",          "IRQ vector",              "irq_handler"),
    VectorLocation(0x0316, "cbinv",  "brk_vector",          "BRK vector",              "brk_handler"),
    VectorLocation(0x0318, "nminv",  "nmi_vector",          "NMI vector",              "nmi_handler"),
    VectorLocation(0x031a, "iopen",  "open_vector",         "OPEN vector",             "open_handler"),
    VectorLocation(0x031c, "iclose", "close_vector",        "CLOSE vector",            "close_handler"),
    VectorLocation(0x031e, "ichkin", "chkin_vector",        "CHKIN vector",            "chkin_handler"),
    VectorLocation(0x0320, "ickout", "chkout_vector",       "CHKOUT vector",           "chkout_handler"),
    VectorLocation(0x0322, "iclrch", "clrchn_vector",       "CLRCHN vector",           "clrchn_handler"),
    VectorLocation(0x0324, "ibasin", "chrin_vector",        "CHRIN vector",            "chrin_handler"),
    VectorLocation(0x0326, "ibsout", "chrout_vector",       "CHROUT vector",           "chrout_handler"),
    VectorLocation(0x0328, "istop",  "stop_vector",         "STOP vector",             "stop_handler"),
    VectorLocation(0x032a, "igetin", "getin_vector",        "GETIN vector",            "getin_handler"),
    VectorLocation(0x032c, "iclall", "clall_vector",        "CLALL vector",            "clall_handler"),
    VectorLocation(0x032e, "usrcmd", "user_command_vector", "user command vector",     "user_command_handler"),
    VectorLocation(0x0330, "iload",  "load_vector",         "LOAD vector",             "load_handler"),
    VectorLocation(0x0332, "isave",  "save_vector",         "SAVE vector",             "save_handler"),
    # BASIC's
    VectorLocation(0x0300, "ierror", "basic_error_vector",     "BASIC error vector",        "basic_error_handler"),
    VectorLocation(0x0302, "imain",  "basic_main_loop_vector", "BASIC main loop vector",    "basic_main_loop_handler"),
    VectorLocation(0x0304, "icrnch", "basic_tokenise_vector",  "BASIC tokenise vector",     "basic_tokenise_handler"),
    VectorLocation(0x0306, "iqplop", "basic_list_token_vector","BASIC list token vector",   "basic_list_token_handler"),
    VectorLocation(0x0308, "igone",  "basic_execute_vector",   "BASIC execute vector",      "basic_execute_handler"),
    VectorLocation(0x030a, "ieval",  "basic_evaluate_vector",  "BASIC evaluate vector",     "basic_evaluate_handler"),
    # The 6502's own (in ROM, or RAM when the ROM is switched out)
    VectorLocation(0xfffa, None, None, "NMI hardware vector",   "nmi_handler"),
    VectorLocation(0xfffe, None, None, "IRQ hardware vector",   "irq_handler"),
]

c64_more_ram_locations = [
    Location(0x033c, 192, "tbuffr", "tape_buffer"),
    Location(0x0400, 1000, "vicscn", "screen_memory"),
    Location(0x07f8, 8, None, "sprite_pointers"),
]

# The 6502's vectors (in the Kernal ROM, or in RAM when a program switches
# the ROM out)
c64_cpu_vectors = [
    Location(0xfffa, 2, None, "hardware_nmi_vector"),
    Location(0xfffc, 2, None, "hardware_reset_vector"),
    Location(0xfffe, 2, None, "hardware_irq_vector"),
]

# Data in the C64's BASIC ROM that programs use: its cold and warm start
# vectors (named with the ROM labels, see c64(rom_labels=...))
c64_rom_locations = [
    Location(0xa000, 2, None, "basic_cold_start_vector"),
    Location(0xa002, 2, None, "basic_warm_start_vector"),
]

# ************************************************************************************************
# C64 hardware: the VIC-II, the SID, the colour RAM and the two CIAs

def _vic_ii():
    result = []
    for n in range(8):
        result.append(Location(0xd000 + 2*n, 1, "sp%dx" % n, "vic_sprite%d_x" % n))
        result.append(Location(0xd001 + 2*n, 1, "sp%dy" % n, "vic_sprite%d_y" % n))
    result += [
        Location(0xd010, 1, "msigx",   "vic_sprites_x_msb"),
        Location(0xd011, 1, "scroly",  "vic_control_1"),
        Location(0xd012, 1, "raster",  "vic_raster_line"),
        Location(0xd013, 1, "lpenx",   "vic_light_pen_x"),
        Location(0xd014, 1, "lpeny",   "vic_light_pen_y"),
        Location(0xd015, 1, "spena",   "vic_sprite_enable"),
        Location(0xd016, 1, "scrolx",  "vic_control_2"),
        Location(0xd017, 1, "yxpand",  "vic_sprite_expand_y"),
        Location(0xd018, 1, "vmcsb",   "vic_memory_setup"),
        Location(0xd019, 1, "vicirq",  "vic_interrupt_status"),
        Location(0xd01a, 1, "irqmask", "vic_interrupt_enable"),
        Location(0xd01b, 1, "spbgpr",  "vic_sprite_priority"),
        Location(0xd01c, 1, "spmc",    "vic_sprite_multicolour"),
        Location(0xd01d, 1, "xxpand",  "vic_sprite_expand_x"),
        Location(0xd01e, 1, "spspcl",  "vic_sprite_sprite_collision"),
        Location(0xd01f, 1, "spbgcl",  "vic_sprite_background_collision"),
        Location(0xd020, 1, "extcol",  "vic_border_colour"),
    ]
    for n in range(4):
        result.append(Location(0xd021 + n, 1, "bgcol%d" % n, "vic_background_colour_%d" % n))
    result.append(Location(0xd025, 1, "spmc0", "vic_sprite_multicolour_0"))
    result.append(Location(0xd026, 1, "spmc1", "vic_sprite_multicolour_1"))
    for n in range(8):
        result.append(Location(0xd027 + n, 1, "sp%dcol" % n, "vic_sprite%d_colour" % n))
    return result

def _sid():
    result = []
    for n in range(3):
        base = 0xd400 + 7*n
        v = n + 1
        result += [
            Location(base + 0, 1, "frelo%d" % v,  "sid_voice%d_frequency_low" % v),
            Location(base + 1, 1, "frehi%d" % v,  "sid_voice%d_frequency_high" % v),
            Location(base + 2, 1, "pwlo%d" % v,   "sid_voice%d_pulse_width_low" % v),
            Location(base + 3, 1, "pwhi%d" % v,   "sid_voice%d_pulse_width_high" % v),
            Location(base + 4, 1, "vcreg%d" % v,  "sid_voice%d_control" % v),
            Location(base + 5, 1, "atdcy%d" % v,  "sid_voice%d_attack_decay" % v),
            Location(base + 6, 1, "surel%d" % v,  "sid_voice%d_sustain_release" % v),
        ]
    result += [
        Location(0xd415, 1, "cutlo",  "sid_filter_cutoff_low"),
        Location(0xd416, 1, "cuthi",  "sid_filter_cutoff_high"),
        Location(0xd417, 1, "reson",  "sid_filter_resonance"),
        Location(0xd418, 1, "sigvol", "sid_volume_filter_mode"),
        Location(0xd419, 1, "potx",   "sid_paddle_x"),
        Location(0xd41a, 1, "poty",   "sid_paddle_y"),
        Location(0xd41b, 1, "random", "sid_voice3_oscillator"),
        Location(0xd41c, 1, "env3",   "sid_voice3_envelope"),
    ]
    return result

def _cia(base, n, commodore_names):
    names = ["port_a", "port_b", "data_direction_a", "data_direction_b",
             "timer_a_low", "timer_a_high", "timer_b_low", "timer_b_high",
             "tod_tenths", "tod_seconds", "tod_minutes", "tod_hours",
             "serial_data", "interrupt_control", "control_a", "control_b"]
    return [Location(base + i, 1, commodore_names[i], "cia%d_%s" % (n, names[i])) for i in range(16)]

c64_hardware_locations = (
    _vic_ii() +
    _sid() +
    [Location(0xd800, 1000, None, "colour_ram")] +
    _cia(0xdc00, 1, ["ciapra", "ciaprb", "ciddra", "ciddrb", "timalo", "timahi", "timblo", "timbhi",
                     "todten", "todsec", "todmin", "todhrs", "ciasdr", "ciaicr", "ciacra", "ciacrb"]) +
    _cia(0xdd00, 2, ["ci2pra", "ci2prb", "c2ddra", "c2ddrb", "ti2alo", "ti2ahi", "ti2blo", "ti2bhi",
                     "to2ten", "to2sec", "to2min", "to2hrs", "ci2sdr", "ci2icr", "ci2cra", "ci2crb"])
)

# The registers whose value is a colour (see colours below), so a colour
# stored in one is named, e.g. 'lda #colour_black : sta vic_border_colour'
c64_colour_registers = [0xd020, 0xd021, 0xd022, 0xd023, 0xd024, 0xd025, 0xd026] + list(range(0xd027, 0xd02f)) + [0x0286]

# ************************************************************************************************
# The Kernal's jump table. Each entry: its address, name, title, and what it
# takes and returns in registers (as for subroutine()). (The VIC-20 has the
# same jump table, without the first three.)

KernalCall = namedtuple("KernalCall", ["addr", "name", "title", "on_entry", "on_exit"])

kernal_jump_table = [
    KernalCall(0xff81, "cint",   "Initialise the screen editor and the VIC-II", None, None),
    KernalCall(0xff84, "ioinit", "Initialise the I/O devices", None, None),
    KernalCall(0xff87, "ramtas", "Test RAM, set the memory pointers and clear the system variables", None, None),
    KernalCall(0xff8a, "restor", "Restore the default Kernal vectors", None, None),
    KernalCall(0xff8d, "vector", "Read or set the Kernal vectors (carry set: read them into the list at X/Y; carry clear: set them from it)",
               {'x': "vector list address (low byte)", 'y': "vector list address (high byte)"}, None),
    KernalCall(0xff90, "setmsg", "Set which Kernal messages are shown (bit 7: control messages, bit 6: error messages)",
               {'a': "message flags"}, None),
    KernalCall(0xff93, "second", "Send a secondary address to a device commanded to listen",
               {'a': "secondary address"}, None),
    KernalCall(0xff96, "tksa",   "Send a secondary address to a device commanded to talk",
               {'a': "secondary address"}, None),
    KernalCall(0xff99, "memtop", "Read or set the top of memory (carry set: read it into X/Y; carry clear: set it from X/Y)",
               {'x': "top of memory (low byte)", 'y': "top of memory (high byte)"}, None),
    KernalCall(0xff9c, "membot", "Read or set the bottom of memory (carry set: read it into X/Y; carry clear: set it from X/Y)",
               {'x': "bottom of memory (low byte)", 'y': "bottom of memory (high byte)"}, None),
    KernalCall(0xff9f, "scnkey", "Scan the keyboard", None, None),
    KernalCall(0xffa2, "settmo", "Set the IEEE bus timeout",
               {'a': "timeout flag"}, None),
    KernalCall(0xffa5, "acptr",  "Read a byte from the serial bus",
               None, {'a': "byte read"}),
    KernalCall(0xffa8, "ciout",  "Send a byte over the serial bus",
               {'a': "byte to send"}, None),
    KernalCall(0xffab, "untlk",  "Command the devices on the serial bus to stop talking", None, None),
    KernalCall(0xffae, "unlsn",  "Command the devices on the serial bus to stop listening", None, None),
    KernalCall(0xffb1, "listen", "Command a device on the serial bus to listen",
               {'a': "device number"}, None),
    KernalCall(0xffb4, "talk",   "Command a device on the serial bus to talk",
               {'a': "device number"}, None),
    KernalCall(0xffb7, "readst", "Read the I/O status",
               None, {'a': "I/O status"}),
    KernalCall(0xffba, "setlfs", "Set the logical file number, device number and secondary address",
               {'a': "logical file number", 'x': "device number", 'y': "secondary address"}, None),
    KernalCall(0xffbd, "setnam", "Set the filename",
               {'a': "filename length", 'x': "filename address (low byte)", 'y': "filename address (high byte)"}, None),
    KernalCall(0xffc0, "open",   "Open a logical file (set up with SETLFS and SETNAM)", None, None),
    KernalCall(0xffc3, "close",  "Close a logical file",
               {'a': "logical file number"}, None),
    KernalCall(0xffc6, "chkin",  "Open a channel for input",
               {'x': "logical file number"}, None),
    KernalCall(0xffc9, "chkout", "Open a channel for output",
               {'x': "logical file number"}, None),
    KernalCall(0xffcc, "clrchn", "Restore the default input and output channels", None, None),
    KernalCall(0xffcf, "chrin",  "Read a character from the input channel",
               None, {'a': "character read"}),
    KernalCall(0xffd2, "chrout", "Output a character",
               {'a': "character to output"}, None),
    KernalCall(0xffd5, "load",   "Load or verify a file (set up with SETLFS and SETNAM)",
               {'a': "0 to load, 1 to verify", 'x': "load address if the secondary address is 0 (low byte)", 'y': "load address if the secondary address is 0 (high byte)"},
               {'x': "end address of the data loaded (low byte)", 'y': "end address of the data loaded (high byte)"}),
    KernalCall(0xffd8, "save",   "Save memory to a file (set up with SETLFS and SETNAM)",
               {'a': "zero page address of the start address", 'x': "end address + 1 (low byte)", 'y': "end address + 1 (high byte)"}, None),
    KernalCall(0xffdb, "settim", "Set the jiffy clock",
               {'a': "jiffy clock (high byte)", 'x': "jiffy clock (middle byte)", 'y': "jiffy clock (low byte)"}, None),
    KernalCall(0xffde, "rdtim",  "Read the jiffy clock",
               None, {'a': "jiffy clock (high byte)", 'x': "jiffy clock (middle byte)", 'y': "jiffy clock (low byte)"}),
    KernalCall(0xffe1, "stop",   "Check the RUN/STOP key (Z set if it's pressed)", None, None),
    KernalCall(0xffe4, "getin",  "Get a character from the input channel (from the keyboard, 0 if there's none)",
               None, {'a': "character read"}),
    KernalCall(0xffe7, "clall",  "Close all files", None, None),
    KernalCall(0xffea, "udtim",  "Update the jiffy clock and check the RUN/STOP key", None, None),
    KernalCall(0xffed, "screen", "Read the screen size",
               None, {'x': "number of columns", 'y': "number of rows"}),
    KernalCall(0xfff0, "plot",   "Read or set the cursor position (carry set: read it into X/Y; carry clear: set it from X/Y)",
               {'x': "cursor row", 'y': "cursor column"}, None),
    KernalCall(0xfff3, "iobase", "Read the address of the I/O devices",
               None, {'x': "I/O base address (low byte)", 'y': "I/O base address (high byte)"}),
]

# ************************************************************************************************
# Well known routines inside the C64's ROMs that programs call, with
# Commodore's names (from the Kernal source, and Microsoft's for BASIC) and
# descriptive names. Each: (address, Commodore's name (None if the source has
# no label there), descriptive name, title, on_entry, on_exit).

RomRoutine = namedtuple("RomRoutine", ["addr", "commodore_name", "name", "title", "on_entry", "on_exit"])

c64_rom_routines = [
    # BASIC
    RomRoutine(0xa474, "ready",  "basic_ready", "Print READY. and return to BASIC's main loop", None, None),
    RomRoutine(0xa7ae, "newstt", "basic_next_statement", "Execute the next BASIC statement", None, None),
    RomRoutine(0xaad7, "crdo",   "basic_print_newline", "Print a carriage return", None, None),
    RomRoutine(0xab1e, "strout", "basic_print_string", "Print the zero-terminated string at A/Y",
               {'a': "string address (low byte)", 'y': "string address (high byte)"}, None),
    RomRoutine(0xbdcd, "linprt", "basic_print_number", "Print the 16-bit number in A/X",
               {'a': "number to print (high byte)", 'x': "number to print (low byte)"}, None),
    # The Kernal
    RomRoutine(0xe544, "clsr",   "clear_screen", "Clear the screen", None, None),
    RomRoutine(0xe566, "nxtd",   "cursor_home", "Move the cursor to the top left of the screen", None, None),
    RomRoutine(0xe716, "prt",    "screen_output_char", "Output a character to the screen",
               {'a': "character to output"}, None),
    RomRoutine(0xea31, "key",    "kernal_irq_handler", "The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)", None, None),
    RomRoutine(0xea7e, "kprend", "kernal_irq_acknowledge", "Acknowledge the CIA 1 interrupt and return from the interrupt", None, None),
    RomRoutine(0xea81, None, "kernal_irq_return", "Restore the registers and return from the interrupt", None, None),
    RomRoutine(0xfce2, "start", "kernal_reset", "The Kernal's reset handler", None, None),
    RomRoutine(0xfe43, "nmi",    "kernal_nmi_handler", "The Kernal's NMI handler", None, None),
    RomRoutine(0xfebc, "prend",  "kernal_nmi_return", "Restore the registers and return from the NMI", None, None),
    RomRoutine(0xff48, "puls",   "kernal_irq_entry", "The Kernal's IRQ and BRK entry point (saves the registers and jumps through the IRQ or BRK vector)", None, None),
]

# ************************************************************************************************
# Values

# The C64's colours, for the VIC-II's colour registers and the colour RAM
colours = {
    0: "colour_black",
    1: "colour_white",
    2: "colour_red",
    3: "colour_cyan",
    4: "colour_purple",
    5: "colour_green",
    6: "colour_blue",
    7: "colour_yellow",
    8: "colour_orange",
    9: "colour_brown",
    10: "colour_light_red",
    11: "colour_dark_grey",
    12: "colour_grey",
    13: "colour_light_green",
    14: "colour_light_blue",
    15: "colour_light_grey",
}

# Device numbers, e.g. for SETLFS
device_numbers = {
    0: "device_keyboard",
    1: "device_datasette",
    2: "device_rs232",
    3: "device_screen",
    4: "device_printer_4",
    5: "device_printer_5",
    8: "device_disk_8",
    9: "device_disk_9",
    10: "device_disk_10",
    11: "device_disk_11",
}

device_descriptions = {
    0: "keyboard",
    1: "datasette",
    2: "RS-232",
    3: "screen",
    4: "printer",
    5: "printer",
    8: "disk drive",
    9: "disk drive",
    10: "disk drive",
    11: "disk drive",
}

# The control codes CHROUT acts on (PETSCII), from c64ref's
# control_codes_c64.txt, described
control_codes = {
    0x03: "STOP",
    0x05: "white",
    0x08: "disable case switching",
    0x09: "enable case switching",
    0x0d: "RETURN",
    0x0e: "lower case",
    0x11: "cursor down",
    0x12: "reverse on",
    0x13: "home",
    0x14: "delete",
    0x1c: "red",
    0x1d: "cursor right",
    0x1e: "green",
    0x1f: "blue",
    0x81: "orange",
    0x83: "RUN",
    0x85: "F1",
    0x86: "F3",
    0x87: "F5",
    0x88: "F7",
    0x89: "F2",
    0x8a: "F4",
    0x8b: "F6",
    0x8c: "F8",
    0x8d: "shifted RETURN",
    0x8e: "upper case",
    0x90: "black",
    0x91: "cursor up",
    0x92: "reverse off",
    0x93: "clear screen",
    0x94: "insert",
    0x95: "brown",
    0x96: "light red",
    0x97: "dark grey",
    0x98: "grey",
    0x99: "light green",
    0x9a: "light blue",
    0x9b: "light grey",
    0x9c: "purple",
    0x9d: "cursor left",
    0x9e: "yellow",
    0x9f: "cyan",
}

# BASIC V2's keywords, by token ($80 upwards)
basic_v2_tokens = [
    "END", "FOR", "NEXT", "DATA", "INPUT#", "INPUT", "DIM", "READ",
    "LET", "GOTO", "RUN", "IF", "RESTORE", "GOSUB", "RETURN", "REM",
    "STOP", "ON", "WAIT", "LOAD", "SAVE", "VERIFY", "DEF", "POKE",
    "PRINT#", "PRINT", "CONT", "LIST", "CLR", "CMD", "SYS", "OPEN",
    "CLOSE", "GET", "NEW", "TAB(", "TO", "FN", "SPC(", "THEN",
    "NOT", "STEP", "+", "-", "*", "/", "^", "AND",
    "OR", ">", "=", "<", "SGN", "INT", "ABS", "USR",
    "FRE", "POS", "SQR", "RND", "LOG", "EXP", "COS", "SIN",
    "TAN", "ATN", "PEEK", "LEN", "STR$", "VAL", "ASC", "CHR$",
    "LEFT$", "RIGHT$", "MID$", "GO",
]
BASIC_TOKEN_SYS = 0x9e
BASIC_TOKEN_REM = 0x8f
BASIC_TOKEN_PI = 0xff
