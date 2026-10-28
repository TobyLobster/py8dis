"""
The Commodore machines' data tables, for commodore.py: names for the memory
locations, hardware registers and Kernal calls, the Kernal's control codes,
the colours, the device numbers and the BASIC tokens, for the C64 and the
VIC-20.

Each memory location has two names: a descriptive one (the default, e.g.
'vic_border_colour') and the one Commodore's documentation uses (from the
Commodore 64 Programmer's Reference Guide and Commodore's own source, or for
the C64's I/O registers from "Mapping the Commodore 64", e.g. 'extcol'),
chosen with commodore.c64(names=...) or vic20(names=...). The Kernal calls
have Commodore's names (e.g. 'chrout') either way.

The C64's names, addresses and Kernal calling conventions are from Michael
Steil's c64ref (https://github.com/mist64/c64ref): src/c64mem/symbols.txt,
src/c64io, src/kernal and src/charset. The VIC-20's are from Commodore's
source for its Kernal and BASIC (https://github.com/mist64/cbmsrc). c64ref's
licence:

    BSD 2-Clause License

    Copyright (c) 2022, Michael Steil
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from collections import namedtuple

# A memory location: its address, its size in bytes (a name is given to each
# byte, e.g. 'tape_buffer+1'), Commodore's name (None if it has none, in which
# case the descriptive name is used) and the descriptive name. (A Commodore
# name can be an offset from another location's, e.g. 'vicreg+1'.)
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
    RomRoutine(0xa474, "readyx", "basic_ready", "Print READY. and return to BASIC's main loop", None, None),
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


# ************************************************************************************************
# The VIC-20. Its Kernal and BASIC are the C64's, for a different machine:
# the same jump table (without its first three entries), and the same
# workspace, with these differences (from Commodore's source): the USR
# function's jump at &0000-&0002 (where the C64 has the 6510's I/O port, and
# &0310-&0312 instead); a shorter screen line link table (25 bytes, for 23
# lines), with LINTMP after it at &00f2; and nothing at &02a1-&02a6.

def _vic20_ram_locations():
    result = [
        Location(0x0000, 1, "usrpok", "usr_jmp"),
        Location(0x0001, 2, "usradd", "usr_address"),
        Location(0x00f2, 1, "lintmp", "screen_scroll_line"),
    ]
    for location in c64_ram_locations:
        if location.addr in (0x0000, 0x0001, 0x0310, 0x0311) or 0x02a1 <= location.addr <= 0x02a6:
            continue
        if location.addr == 0x00d9:
            location = location._replace(size=25)
        result.append(location)
    return sorted(result)

vic20_ram_locations = _vic20_ram_locations()

# The screen and its colour RAM move with the RAM expansion: with 8K or more
# in block 1 (&2000), the screen is at &1000 and the colour RAM at &9400;
# otherwise at &1e00 and &9600. (22 columns by 23 rows.)
VIC20_SCREEN_SIZE = 22 * 23

def vic20_screen_locations(expanded_8k):
    screen = 0x1000 if expanded_8k else 0x1e00
    colour = 0x9400 if expanded_8k else 0x9600
    return [
        Location(screen, VIC20_SCREEN_SIZE, "vicscn", "screen_memory"),
        Location(colour, VIC20_SCREEN_SIZE, "viccol", "colour_ram"),
    ]

def _vic():
    names = ["horizontal_position", "vertical_position", "columns", "rows", "raster_line", "memory_setup",
             "light_pen_x", "light_pen_y", "paddle_x", "paddle_y", "voice1_frequency", "voice2_frequency",
             "voice3_frequency", "noise_frequency", "volume_aux_colour", "background_border_colour"]
    return [Location(0x9000 + i, 1, "vicreg" if i == 0 else "vicreg+%d" % i, "vic_" + names[i]) for i in range(16)]

def _via(base, n):
    names = ["port_b", "port_a", "data_direction_b", "data_direction_a",
             "timer1_low", "timer1_high", "timer1_latch_low", "timer1_latch_high", "timer2_low", "timer2_high",
             "shift_register", "auxiliary_control", "peripheral_control", "interrupt_flags", "interrupt_enable",
             "port_a_no_handshake"]
    commodore_names = ["orb", "orah", "ddrb", "ddra", "t1l", "t1h", "t1ll", "t1lh", "t2l", "t2h",
                       "sr", "acr", "pcr", "ifr", "ier", "ora"]
    return [Location(base + i, 1, "d%d%s" % (n, commodore_names[i]), "via%d_%s" % (n, names[i])) for i in range(16)]

vic20_hardware_locations = (
    [Location(0x8000, 4096, None, "character_rom")] +
    _vic() +
    _via(0x9110, 1) +
    _via(0x9120, 2)
)

vic20_rom_locations = [
    Location(0xc000, 2, None, "basic_cold_start_vector"),
    Location(0xc002, 2, None, "basic_warm_start_vector"),
]

vic20_rom_routines = [
    # BASIC
    RomRoutine(0xc474, "ready",  "basic_ready", "Print READY. and return to BASIC's main loop", None, None),
    RomRoutine(0xc7ae, "newstt", "basic_next_statement", "Execute the next BASIC statement", None, None),
    RomRoutine(0xcad7, "crdo",   "basic_print_newline", "Print a carriage return", None, None),
    RomRoutine(0xcb1e, "strout", "basic_print_string", "Print the zero-terminated string at A/Y",
               {'a': "string address (low byte)", 'y': "string address (high byte)"}, None),
    RomRoutine(0xddcd, "linprt", "basic_print_number", "Print the 16-bit number in A/X",
               {'a': "number to print (high byte)", 'x': "number to print (low byte)"}, None),
    # The Kernal
    RomRoutine(0xe55f, "clsr",   "clear_screen", "Clear the screen", None, None),
    RomRoutine(0xe581, "nxtd",   "cursor_home", "Move the cursor to the top left of the screen", None, None),
    RomRoutine(0xe742, "prt",    "screen_output_char", "Output a character to the screen",
               {'a': "character to output"}, None),
    RomRoutine(0xeabf, "key",    "kernal_irq_handler", "The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)", None, None),
    RomRoutine(0xeb15, "kprend", "kernal_irq_acknowledge", "Acknowledge the VIA 2 interrupt and return from the interrupt", None, None),
    RomRoutine(0xeb18, None,     "kernal_irq_return", "Restore the registers and return from the interrupt", None, None),
    RomRoutine(0xfd22, "start",  "kernal_reset", "The Kernal's reset handler", None, None),
    RomRoutine(0xfea9, "nmi",    "kernal_nmi_handler", "The Kernal's NMI handler", None, None),
    RomRoutine(0xff56, "prend",  "kernal_nmi_return", "Restore the registers and return from the NMI", None, None),
    RomRoutine(0xff72, "puls",   "kernal_irq_entry", "The Kernal's IRQ and BRK entry point (saves the registers and jumps through the IRQ or BRK vector)", None, None),
]

# The VIC-20's colours (the text colour at &0286 can be the first 8)
vic20_colours = {
    0: "colour_black",
    1: "colour_white",
    2: "colour_red",
    3: "colour_cyan",
    4: "colour_purple",
    5: "colour_green",
    6: "colour_blue",
    7: "colour_yellow",
    8: "colour_orange",
    9: "colour_light_orange",
    10: "colour_pink",
    11: "colour_light_cyan",
    12: "colour_light_purple",
    13: "colour_light_green",
    14: "colour_light_blue",
    15: "colour_light_yellow",
}
vic20_colour_registers = [0x0286]

# The VIC-20's control codes: the C64's, without its extra colours (from
# c64ref's control_codes_vic-20.txt, which also leaves out $08 and $09, but
# the VIC-20's Kernal source handles those as the C64's does)
vic20_control_codes = {c: d for c, d in control_codes.items() if c not in (0x81, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b)}


# ************************************************************************************************
# The C128 and the Plus/4 (and C16). Their workspace is from Commodore's source
# (commodoresource.py, which has hundreds of locations each). The
# descriptive names are: a hand-written name below; else the C64's
# descriptive name for a location with the same Commodore name (e.g.
# 'txttab', BASIC's start, is 'basic_program_start' wherever it is), unless
# it's listed below as meaning something else; else Commodore's name. (So
# with names="descriptive", the less common locations still have
# Commodore's names.)

import commodoresource

_c64_descriptive_names = dict(
    [(l.commodore_name, l.name) for l in c64_ram_locations if l.commodore_name] +
    [(v.commodore_name, v.name) for v in c64_vectors if v.commodore_name] +
    [(l.commodore_name, l.name) for l in c64_more_ram_locations if l.commodore_name])

def _workspace(declarations, descriptive_names):
    """Locations for the workspace declared in Commodore's source, with the
    descriptive names (None in descriptive_names means Commodore's)"""
    result = []
    for addr, size, commodore_name in declarations:
        if addr in descriptive_names:
            name = descriptive_names[addr] or commodore_name
        else:
            name = _c64_descriptive_names.get(commodore_name, commodore_name)
        result.append(Location(addr, size, commodore_name, name))
    return result

# The C128's: its own locations, and those whose Commodore name is the C64's
# for something else
c128_descriptive_names = {
    # JSRFAR/JMPFAR's (and the monitor's) registers
    0x0002: "far_call_bank",
    0x0003: "far_call_pc_high",
    0x0004: "far_call_pc_low",
    0x0005: "far_call_status",
    0x0006: "far_call_a",
    0x0007: "far_call_x",
    0x0008: "far_call_y",
    0x0009: "far_call_stack_pointer",
    0x00c5: "tape_data",
    0x00c6: "io_bank",
    0x00c7: "filename_bank",
    0x00ce: "primm_string_ptr",
    0x00d7: "screen_mode_40_80",
    0x00d8: "graphics_mode",
    0x00d9: "vic_charset_rom_flag",
    0x00e4: "window_bottom",
    0x00e5: "window_top",
    0x00e6: "window_left",
    0x00e7: "window_right",
    0x00ed: "screen_lines",
    0x00ee: "screen_columns",
    # The routines copied to RAM that reach any bank
    0x02a2: "fetch_any_bank",
    0x02af: "stash_any_bank",
    0x02be: "compare_any_bank",
    0x02cd: "jsrfar_routine",
    0x02e3: "jmpfar_routine",
    0x030c: "basic_escape_link_vector",
    0x030e: "basic_escape_print_vector",
    0x0310: "basic_escape_execute_vector",
    0x0312: "basic_time_vector",
    0x0314: "irq_vector",
    0x0316: "brk_vector",
    0x0318: "nmi_vector",
    0x032e: "monitor_command_vector",
    0x0334: "editor_control_vector",
    0x0336: "editor_shift_vector",
    0x0338: "editor_escape_vector",
    0x033a: "editor_keyscan_vector",
    0x033c: "editor_store_key_vector",
    0x033e: "keyboard_decode_tables",
    0x0a00: "system_restart_vector",
    0x0a02: "kernal_init_status",
    0x0a04: "reset_or_nmi_status",
    0x0a07: "os_memory_end",
    0x0a1c: "fast_serial_flag",
    0x0a1d: "jiffy_countdown",
    0x0a21: "pause_flag",
    0x0a26: "vic_cursor_mode",
    0x0a2c: "vic_screen_charset_base",
    0x0a2d: "vic_bitmap_base",
    0x0a2e: "vdc_screen_base",
    0x0a2f: "vdc_attribute_base",
    0x0a34: "vic_split_raster",
    0x0a37: "saved_cpu_speed",
    0x1000: "function_key_lengths",
    0x100a: "function_key_strings",
}

# The Plus/4's
plus4_descriptive_names = {
    0x0000: "cpu_port_direction",
    0x0001: "cpu_port",
    0x00c6: None,                   # (a shift mode, not the C64's key pressed)
    0x030c: "basic_escape_link_vector",
    0x030e: "basic_escape_print_vector",
    0x0310: "basic_escape_execute_vector",
    0x0312: "basic_time_vector",
    0x0333: "tape_buffer",
    0x0567: "function_key_buffer",
}

c128_workspace_locations = _workspace(commodoresource.c128_workspace, c128_descriptive_names)
plus4_workspace_locations = _workspace(commodoresource.plus4_workspace, plus4_descriptive_names)

# The Kernal's RAM vectors, for the snippet that recognises a program setting
# one: (address, description, handler name)
def _vectors(locations, descriptions):
    by_addr = {l.addr: l for l in locations}
    return [VectorLocation(addr, by_addr[addr].commodore_name, by_addr[addr].name, description, handler)
            for addr, description, handler in descriptions]

c128_vectors = _vectors(c128_workspace_locations, [
    (0x0314, "IRQ vector", "irq_handler"),
    (0x0316, "BRK vector", "brk_handler"),
    (0x0318, "NMI vector", "nmi_handler"),
    (0x031a, "OPEN vector", "open_handler"),
    (0x031c, "CLOSE vector", "close_handler"),
    (0x031e, "CHKIN vector", "chkin_handler"),
    (0x0320, "CHKOUT vector", "chkout_handler"),
    (0x0322, "CLRCHN vector", "clrchn_handler"),
    (0x0324, "CHRIN vector", "chrin_handler"),
    (0x0326, "CHROUT vector", "chrout_handler"),
    (0x0328, "STOP vector", "stop_handler"),
    (0x032a, "GETIN vector", "getin_handler"),
    (0x032c, "CLALL vector", "clall_handler"),
    (0x032e, "monitor command vector", "monitor_command_handler"),
    (0x0330, "LOAD vector", "load_handler"),
    (0x0332, "SAVE vector", "save_handler"),
    (0x0300, "BASIC error vector", "basic_error_handler"),
    (0x0302, "BASIC main loop vector", "basic_main_loop_handler"),
    (0x0304, "BASIC tokenise vector", "basic_tokenise_handler"),
    (0x0306, "BASIC list token vector", "basic_list_token_handler"),
    (0x0308, "BASIC execute vector", "basic_execute_handler"),
    (0x030a, "BASIC evaluate vector", "basic_evaluate_handler"),
    (0x030c, "BASIC escape link vector", "basic_escape_link_handler"),
    (0x030e, "BASIC escape print vector", "basic_escape_print_handler"),
    (0x0310, "BASIC escape execute vector", "basic_escape_execute_handler"),
    (0x0334, "editor control vector", "editor_control_handler"),
    (0x0336, "editor shift vector", "editor_shift_handler"),
    (0x0338, "editor escape vector", "editor_escape_handler"),
    (0x033a, "editor keyscan vector", "editor_keyscan_handler"),
    (0x033c, "editor store key vector", "editor_store_key_handler"),
]) + [VectorLocation(0xfffa, None, None, "NMI hardware vector", "nmi_handler"),
      VectorLocation(0xfffe, None, None, "IRQ hardware vector", "irq_handler")]

plus4_vectors = _vectors(plus4_workspace_locations, [
    (0x0314, "IRQ vector", "irq_handler"),
    (0x0316, "BRK vector", "brk_handler"),
    (0x0318, "OPEN vector", "open_handler"),
    (0x031a, "CLOSE vector", "close_handler"),
    (0x031c, "CHKIN vector", "chkin_handler"),
    (0x031e, "CHKOUT vector", "chkout_handler"),
    (0x0320, "CLRCHN vector", "clrchn_handler"),
    (0x0322, "CHRIN vector", "chrin_handler"),
    (0x0324, "CHROUT vector", "chrout_handler"),
    (0x0326, "STOP vector", "stop_handler"),
    (0x0328, "GETIN vector", "getin_handler"),
    (0x032a, "CLALL vector", "clall_handler"),
    (0x032c, "user command vector", "user_command_handler"),
    (0x032e, "LOAD vector", "load_handler"),
    (0x0330, "SAVE vector", "save_handler"),
    (0x0300, "BASIC error vector", "basic_error_handler"),
    (0x0302, "BASIC main loop vector", "basic_main_loop_handler"),
    (0x0304, "BASIC tokenise vector", "basic_tokenise_handler"),
    (0x0306, "BASIC list token vector", "basic_list_token_handler"),
    (0x0308, "BASIC execute vector", "basic_execute_handler"),
    (0x030a, "BASIC evaluate vector", "basic_evaluate_handler"),
    (0x030c, "BASIC escape link vector", "basic_escape_link_handler"),
    (0x030e, "BASIC escape print vector", "basic_escape_print_handler"),
    (0x0310, "BASIC escape execute vector", "basic_escape_execute_handler"),
]) + [VectorLocation(0xfffa, None, None, "NMI hardware vector", "nmi_handler"),
      VectorLocation(0xfffe, None, None, "IRQ hardware vector", "irq_handler")]

# The C128's hardware: the C64's VIC-II, SID and CIAs (with Commodore's
# names in its C128 source: 'vicreg+n', 'sidreg+n', 'd1pra'), the VIC-II's two
# new registers, the MMU, the VDC and the colour RAM
def _c128_hardware():
    result = []
    vic_ii = [l for l in c64_hardware_locations if 0xd000 <= l.addr < 0xd400]
    for l in vic_ii:
        result.append(l._replace(commodore_name="vicreg" if l.addr == 0xd000 else "vicreg+%d" % (l.addr - 0xd000)))
    result += [
        Location(0xd02f, 1, "vicreg+47", "vic_keyboard_lines"),
        Location(0xd030, 1, "vicreg+48", "vic_clock_speed"),
    ]
    for l in c64_hardware_locations:
        if 0xd400 <= l.addr < 0xd800:
            result.append(l._replace(commodore_name="sidreg" if l.addr == 0xd400 else "sidreg+%d" % (l.addr - 0xd400)))
    result += [
        Location(0xd500, 1, "mmucrl", "mmu_configuration_io"),
        Location(0xd501, 1, "pcra",   "mmu_preconfiguration_a"),
        Location(0xd502, 1, "pcrb",   "mmu_preconfiguration_b"),
        Location(0xd503, 1, "pcrc",   "mmu_preconfiguration_c"),
        Location(0xd504, 1, "pcrd",   "mmu_preconfiguration_d"),
        Location(0xd505, 1, "mmumcr", "mmu_mode_configuration"),
        Location(0xd506, 1, "mmurcr", "mmu_ram_configuration"),
        Location(0xd507, 1, "mmup0l", "mmu_page0_low"),
        Location(0xd508, 1, "mmup0h", "mmu_page0_high"),
        Location(0xd509, 1, "mmup1l", "mmu_page1_low"),
        Location(0xd50a, 1, "mmup1h", "mmu_page1_high"),
        Location(0xd50b, 1, "mmuver", "mmu_version"),
        Location(0xd600, 1, "vdcadr", "vdc_address"),
        Location(0xd601, 1, "vdcdat", "vdc_data"),
        Location(0xd800, 1024, None, "colour_ram"),
    ]
    c128_cia_names = ["pra", "prb", "ddra", "ddrb", "t1l", "t1h", "t2l", "t2h", "tod1", "tods", "todm", "todh", "sdr", "icr", "cra", "crb"]
    for l in c64_hardware_locations:
        if 0xdc00 <= l.addr < 0xde00:
            n = 1 if l.addr < 0xdd00 else 2
            result.append(l._replace(commodore_name="d%d%s" % (n, c128_cia_names[l.addr & 0x0f])))
    result += [
        Location(0xff00, 1, "mmucr", "mmu_configuration"),
        Location(0xff01, 1, "lcra",  "mmu_load_configuration_a"),
        Location(0xff02, 1, "lcrb",  "mmu_load_configuration_b"),
        Location(0xff03, 1, "lcrc",  "mmu_load_configuration_c"),
        Location(0xff04, 1, "lcrd",  "mmu_load_configuration_d"),
    ]
    return result

c128_hardware_locations = _c128_hardware()

# The Plus/4's hardware: the TED (with the names in its Kernal source where
# there are any), the ACIA, the 6529 ports and the ROM bank select
plus4_hardware_locations = [
    Location(0xfd00, 1, "acia", "acia_data"),
    Location(0xfd01, 1, "acia+1", "acia_status"),
    Location(0xfd02, 1, "acia+2", "acia_command"),
    Location(0xfd03, 1, "acia+3", "acia_control"),
    Location(0xfd10, 1, "xport", "user_port"),
    Location(0xfd30, 1, None, "keyboard_latch"),
    Location(0xfdd0, 16, "bnksel", "rom_bank_select"),
    Location(0xff00, 1, "timr1l", "ted_timer1_low"),
    Location(0xff01, 1, "timr1h", "ted_timer1_high"),
    Location(0xff02, 1, "timr2l", "ted_timer2_low"),
    Location(0xff03, 1, "timr2h", "ted_timer2_high"),
    Location(0xff04, 1, "timr3l", "ted_timer3_low"),
    Location(0xff05, 1, "timr3h", "ted_timer3_high"),
    Location(0xff06, 1, "tedvcr", "ted_control_1"),
    Location(0xff07, 1, None, "ted_control_2"),
    Location(0xff08, 1, "keybrd", "ted_keyboard_latch"),
    Location(0xff09, 1, "tedirq", "ted_interrupt_status"),
    Location(0xff0a, 1, "tedicr", "ted_interrupt_enable"),
    Location(0xff0b, 1, None, "ted_raster_compare"),
    Location(0xff0c, 1, "tedcrh", "ted_cursor_high"),
    Location(0xff0d, 1, "tedcrl", "ted_cursor_low"),
    Location(0xff0e, 1, "tedmlo", "ted_voice1_frequency_low"),
    Location(0xff0f, 1, "tedmlo+1", "ted_voice2_frequency_low"),
    Location(0xff10, 1, "tedmhi", "ted_voice2_frequency_high"),
    Location(0xff11, 1, "tedvoi", "ted_sound_control"),
    Location(0xff12, 1, "tedmhi+2", "ted_bitmap_base_voice1_high"),
    Location(0xff13, 1, "tedcbr", "ted_character_base"),
    Location(0xff14, 1, None, "ted_video_matrix_base"),
    Location(0xff15, 1, None, "ted_background_colour_0"),
    Location(0xff16, 1, None, "ted_background_colour_1"),
    Location(0xff17, 1, None, "ted_background_colour_2"),
    Location(0xff18, 1, None, "ted_background_colour_3"),
    Location(0xff19, 1, None, "ted_border_colour"),
    Location(0xff1a, 1, None, "ted_cursor_reload_high"),
    Location(0xff1b, 1, None, "ted_cursor_reload_low"),
    Location(0xff1c, 1, None, "ted_raster_line_high"),
    Location(0xff1d, 1, None, "ted_raster_line_low"),
    Location(0xff1e, 1, None, "ted_raster_column"),
    Location(0xff1f, 1, None, "ted_flash_counter"),
    Location(0xff3e, 1, "romon", "ted_rom_select"),
    Location(0xff3f, 1, "romoff", "ted_ram_select"),
]

# The Plus/4's screen and its attributes (colour and luminance)
plus4_screen_locations = [
    Location(0x0800, 1000, "tedatr", "colour_ram"),
    Location(0x0c00, 1000, "tedscn", "screen_memory"),
]

# The C128's and Plus/4's additions to the Kernal's jump table
c128_jump_table_additions = [
    KernalCall(0xff47, "spin_spout", "Set up the fast serial port for input (carry clear) or output (carry set)", None, None),
    KernalCall(0xff4a, "close_all", "Close all files on a device",
               {'a': "device number"}, None),
    KernalCall(0xff4d, "c64mode", "Switch to C64 mode (doesn't return)", None, None),
    KernalCall(0xff50, "dma_call", "Send a command to a DMA device (e.g. a RAM expansion)",
               {'x': "bank", 'y': "DMA command"}, None),
    KernalCall(0xff53, "boot_call", "Boot from a disk",
               {'a': "drive number (as a character)", 'x': "device number"}, None),
    KernalCall(0xff56, "phoenix", "Start the function ROMs, then boot from a disk", None, None),
    KernalCall(0xff59, "lkupla", "Look up a logical file number (carry clear if it's found)",
               {'a': "logical file number"}, {'x': "device number", 'y': "secondary address"}),
    KernalCall(0xff5c, "lkupsa", "Look up a secondary address (carry clear if it's found)",
               {'y': "secondary address"}, {'a': "logical file number", 'x': "device number"}),
    KernalCall(0xff5f, "swapper", "Switch between the 40 and 80 column screens", None, None),
    KernalCall(0xff62, "dlchr", "Copy the character set to the VDC's RAM", None, None),
    KernalCall(0xff65, "pfkey", "Program a function key",
               {'a': "zero page address of the string's address", 'x': "key number", 'y': "string length"}, None),
    KernalCall(0xff68, "setbnk", "Set the banks for LOAD, SAVE and VERIFY, and for the filename",
               {'a': "bank for the data", 'x': "bank for the filename"}, None),
    KernalCall(0xff6b, "getcfg", "Get the MMU configuration for a bank",
               {'x': "bank"}, {'a': "MMU configuration"}),
    KernalCall(0xff6e, "jsrfar", "Call a routine in another bank (set up at $02-$08)", None, None),
    KernalCall(0xff71, "jmpfar", "Jump to a routine in another bank (set up at $02-$08)", None, None),
    KernalCall(0xff74, "indfet", "Read a byte from any bank (LDA (pointer),Y)",
               {'a': "zero page address of the pointer", 'x': "bank", 'y': "index"}, {'a': "byte read"}),
    KernalCall(0xff77, "indsta", "Write a byte to any bank (STA (pointer),Y; the pointer's zero page address at $02b9)",
               {'a': "byte to write", 'x': "bank", 'y': "index"}, None),
    KernalCall(0xff7a, "indcmp", "Compare a byte in any bank (CMP (pointer),Y; the pointer's zero page address at $02c8)",
               {'a': "byte to compare", 'x': "bank", 'y': "index"}, None),
    KernalCall(0xff7d, "primm", "Print the zero-terminated string that follows the JSR", None, None),
]

plus4_jump_table_additions = [
    KernalCall(0xff4c, "print", "Output a character to the screen",
               {'a': "character to output"}, None),
    KernalCall(0xff4f, "primm", "Print the zero-terminated string that follows the JSR", None, None),
    KernalCall(0xff52, "monitr", "Enter the machine code monitor", None, None),
]

c128_rom_routines = [
    # BASIC
    RomRoutine(0x4db7, "readyx", "basic_ready", "Print READY. and return to BASIC's main loop", None, None),
    RomRoutine(0x4af6, "newstt", "basic_next_statement", "Execute the next BASIC statement", None, None),
    RomRoutine(0x5598, "crdo",   "basic_print_newline", "Print a carriage return", None, None),
    RomRoutine(0x55e2, "strout", "basic_print_string", "Print the zero-terminated string at A/Y",
               {'a': "string address (low byte)", 'y': "string address (high byte)"}, None),
    RomRoutine(0x8e32, "linprt", "basic_print_number", "Print the 16-bit number in A/X",
               {'a': "number to print (high byte)", 'x': "number to print (low byte)"}, None),
    # The screen editor
    RomRoutine(0xc142, "clsr",   "clear_screen", "Clear the current screen window", None, None),
    RomRoutine(0xc72d, "print",  "screen_output_char", "Output a character to the screen",
               {'a': "character to output"}, None),
    # The Kernal
    RomRoutine(0xe000, "start",  "kernal_reset", "The Kernal's reset handler", None, None),
    RomRoutine(0xe224, "c128mode", "c128_mode", "Start the C128 in C128 mode", None, None),
    RomRoutine(0xfa40, "nnmi",   "kernal_nmi_handler", "The Kernal's NMI handler", None, None),
    RomRoutine(0xfa65, "nirq",   "kernal_irq_handler", "The Kernal's IRQ handler (blinks the cursor, scans the keyboard etc., then returns from the interrupt)", None, None),
    RomRoutine(0xff05, "nmi",    "kernal_nmi_entry", "The Kernal's NMI entry point (saves the registers and jumps through the NMI vector)", None, None),
    RomRoutine(0xff17, "irq",    "kernal_irq_entry", "The Kernal's IRQ and BRK entry point (saves the registers and jumps through the IRQ or BRK vector)", None, None),
    RomRoutine(0xff33, "prend",  "kernal_irq_return", "Restore the registers and return from the interrupt", None, None),
]

plus4_rom_routines = [
    # BASIC
    RomRoutine(0x8703, "readyx", "basic_ready", "Print READY. and return to BASIC's main loop", None, None),
    RomRoutine(0x8bdc, "newstt", "basic_next_statement", "Execute the next BASIC statement", None, None),
    RomRoutine(0x903e, "crdo",   "basic_print_newline", "Print a carriage return", None, None),
    RomRoutine(0x9088, "strout", "basic_print_string", "Print the zero-terminated string at A/Y",
               {'a': "string address (low byte)", 'y': "string address (high byte)"}, None),
    RomRoutine(0xa45f, "linprt", "basic_print_number", "Print the 16-bit number in A/X",
               {'a': "number to print (high byte)", 'x': "number to print (low byte)"}, None),
    # The Kernal
    RomRoutine(0xd88b, "clsr",   "clear_screen", "Clear the screen", None, None),
    RomRoutine(0xf2a4, "start",  "kernal_reset", "The Kernal's reset handler", None, None),
    RomRoutine(0xfcb3, "puls",   "kernal_irq_entry", "The Kernal's IRQ and BRK entry point (saves the registers and jumps through the IRQ or BRK vector)", None, None),
    RomRoutine(0xfcc3, None,     "kernal_irq_return", "Restore the registers and return from the interrupt", None, None),
]

# The C128's colour registers: the VIC-II's, as on the C64. (The text colour
# at &00f1 isn't one, since in 80 columns it's a VDC attribute, not a colour
# number.)
c128_colour_registers = [0xd020, 0xd021, 0xd022, 0xd023, 0xd024, 0xd025, 0xd026] + list(range(0xd027, 0xd02f))
