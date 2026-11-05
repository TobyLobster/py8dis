"""
Acorn Atom tables

The data acornatom.py uses for the Acorn Atom: its OS entry points, its
vectors, the control codes OSWRCH acts on, the kernel routines programs call,
the OS and BASIC workspace, the hardware (the 8255 PPI, the VIA and the ROM
latch) and the regions of memory.

Checked against the kernel ROM (#F000-#FFFF, CRC32 c604db3d), with Acorn's
Atomic Theory and Practice, chapter 25 (as on mdfs.net), and the commented
kernel disassembly in floooh/emu-info (acorn/kernel.dis.txt). Addresses are in
the Atom's own notation (#) in the comments.
"""

# The OS entry points, in address order: (address, name, the vector it
# jumps through or None). OSECHO, OSASCI and OSCRLF don't jump through a
# vector: OSECHO calls OSRDCH then falls through into OSASCI, which writes
# CR as LF CR, falling through into OSCRLF (LF, CR) and OSWRCH.
atom_os_calls = [
    (0xffcb, "osshut", 0x021a),
    (0xffce, "osfind", 0x0218),
    (0xffd1, "osbput", 0x0216),
    (0xffd4, "osbget", 0x0214),
    (0xffd7, "osstar", 0x0212),
    (0xffda, "osrdar", 0x0210),
    (0xffdd, "ossave", 0x020e),
    (0xffe0, "osload", 0x020c),
    (0xffe3, "osrdch", 0x020a),
    (0xffe6, "osecho", None),
    (0xffe9, "osasci", None),
    (0xffed, "oscrlf", None),
    (0xfff4, "oswrch", 0x0208),
    (0xfff7, "oscli", 0x0206),
]

# The vectors at #0200-#021F: {address: (name, description)}. The OS calls
# jump through them (see atom_os_calls), and the 6502's NMI, BRK and IRQ go
# through the first three. IN1VEC and IN2VEC are Econet's.
atom_vectors = {
    0x0200: ("nmivec", "NMI vector"),
    0x0202: ("brkvec", "BRK vector"),
    0x0204: ("irqvec", "IRQ vector"),
    0x0206: ("comvec", "command line vector"),
    0x0208: ("wrcvec", "write character vector"),
    0x020a: ("rdcvec", "read character vector"),
    0x020c: ("lodvec", "load file vector"),
    0x020e: ("savvec", "save file vector"),
    0x0210: ("rdrvec", "read file arguments vector"),
    0x0212: ("strvec", "store file arguments vector"),
    0x0214: ("bgtvec", "get byte vector"),
    0x0216: ("bptvec", "put byte vector"),
    0x0218: ("fndvec", "open file vector"),
    0x021a: ("shtvec", "close file vector"),
    0x021c: ("in1vec", "Econet vector 1"),
    0x021e: ("in2vec", "Econet vector 2"),
}

# What OSWRCH does with each control code it acts on (the others below 32
# are ignored), for the comments on the characters code writes. (From the
# kernel's OSWRCH at #FE52: #FCEA, and the table at #FECB.)
atom_control_codes = {
    2:   "Start sending characters to the printer",
    3:   "Stop sending characters to the printer",
    6:   "Start screen output (in text mode)",
    7:   "Sound the bell",
    8:   "Move the cursor back one character",
    9:   "Move the cursor forward one character",
    10:  "Move the cursor down one line",
    11:  "Move the cursor up one line",
    12:  "Clear the screen",
    13:  "Move the cursor to the start of the line",
    14:  "Page mode on",
    15:  "Page mode off",
    21:  "Stop screen output",
    27:  "Escape: start screen output, in text mode",
    30:  "Move the cursor home",
    127: "Delete the character before the cursor",
}

# Kernel routines that programs call: (address, name, title, on_entry). The
# first prints the string after the JSR (see acornatom.atom()).
atom_kernel_routines = [
    (0xf7d1, "print_inline_string", "Print the string after the JSR, up to a byte with bit 7 set, and carry on there", None),
    (0xf7ee, "print_hex_4_bytes", "Print the four bytes at X in hex: X+1, X, a space, X+3, X+2 and a space", {'x': "zero page address"}),
    (0xf7f1, "print_hex_2_bytes", "Print the two bytes at X in hex, high byte first, and a space", {'x': "zero page address"}),
    (0xf7fa, "print_hex_space", "Print A in hex, and a space", {'a': "byte to print"}),
    (0xf7fd, "print_space", "Print a space", None),
    (0xf802, "print_hex", "Print A in hex", {'a': "byte to print"}),
    (0xf80b, "print_hex_digit", "Print the low four bits of A as a hex digit", {'a': "value to print (bits 0-3)"}),
    (0xf876, "skip_input_buffer_spaces", "Skip spaces in the input buffer from #0100+Y (A is the next character)", {'y': "offset in the input buffer"}),
    (0xfb8a, "wait_tenth_second", "Wait for six field flybacks (a tenth of a second)", None),
    (0xfd1a, "wrch_bell", "Sound the bell (as OSWRCH does for character 7)", None),
    (0xfe60, "restore_xy_and_return", "Restore X and Y from #E4 and #E5, pull the flags and return (as OSWRCH and OSRDCH end)", None),
    (0xfe66, "wait_for_flyback", "Wait for the start of the next field flyback", None),
    (0xfe6b, "wait_for_flyback_or_now", "Wait for the field flyback, unless it's under way", None),
    (0xfe71, "scan_keyboard", "Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32", None),
    (0xfec5, "find_control_code", "Find A in the table of control codes and keys at #FECB, from X down (X is its index)", {'a': "character", 'x': "index to search down from (#0A for OSWRCH's control codes, #17 for OSRDCH's keys)"}),
    (0xfefb, "send_to_printer", "Send A to the printer if it's on (2 turns it on and 3 off; the character at #FE isn't sent)", {'a': "character"}),
    # The kernel's own handlers, the vectors' defaults (copied from #FF9A on
    # reset), which code that replaces one often passes calls on to
    (0xf8ef, "kernel_cli", "Run the command in the input buffer (the kernel's OSCLI, COMVEC's default)", None),
    (0xf96e, "kernel_load", "Load a file (the kernel's OSLOAD, LODVEC's default)", None),
    (0xfae5, "kernel_save", "Save a file (the kernel's OSSAVE, SAVVEC's default)", None),
    (0xfbee, "kernel_bget", "Read a byte from tape (the kernel's OSBGET, BGTVEC's default)", None),
    (0xfc38, "kernel_find", "Print 'PLAY TAPE' or 'RECORD TAPE' (the kernel's OSFIND, FNDVEC's default)", None),
    (0xfc7c, "kernel_bput", "Write a byte to tape (the kernel's OSBPUT, BPTVEC's default)", None),
    (0xfe52, "kernel_wrch", "Write character A (the kernel's OSWRCH, WRCVEC's default)", None),
    (0xfe94, "kernel_rdch", "Read a character into A (the kernel's OSRDCH, RDCVEC's default)", None),
]

# The OS's and BASIC's workspace: (address, name, length). A length of more
# than one names the bytes after the first e.g. 'rnd_seed+1'.
atom_workspace = [
    # BASIC
    (0x0000, "basic_error_number", 1),
    (0x0001, "basic_line_number", 2),
    (0x0003, "parsing_ptr_offset", 1),      # (Y for parsing_ptr_low)
    (0x0004, "workspace_stack_pointer", 1), # (X for the workspace stack)
    (0x0005, "parsing_ptr_low", 1),         # (the text being run)
    (0x0006, "parsing_ptr_high", 1),
    (0x0008, "rnd_seed", 5),
    (0x0010, "basic_error_handler", 2),
    (0x0012, "text_space_page", 1),
    # The OS
    (0x00de, "screen_line_address", 2),
    (0x00e0, "cursor_column", 1),
    (0x00e1, "cursor_mask", 1),
    (0x00e6, "page_mode_count", 1),
    (0x00e7, "lock_flag", 1),
    (0x00ea, "nomon_flag", 1),
    (0x00fe, "printer_ignore_char", 1),
    (0x00ff, "irq_save_a", 1),
    (0x0100, "input_buffer", 1),
    (0x0140, "string_buffer", 1),
    (0x03fe, "plot_vector", 2),
]

# BASIC's workspace stack, where it evaluates expressions: four tables of
# ATOM_WORKSPACE_STACK_LEVELS bytes, one for each byte of a level's 32-bit
# value (least significant first), indexed by workspace_stack_pointer. Code
# reads the levels below with e.g. 'lda int_workspace_stack_low-1,x', so
# the two bytes before each table are named from it (e.g. #24 is
# int_workspace_stack_mid1-1, not int_workspace_stack_low+14). (These names,
# and parsing_ptr's and workspace_stack_pointer's above, are from Toby
# Nelson's annotation of the floating point ROM: see
# examples/python/atom_float_rom.py.)
ATOM_WORKSPACE_STACK_LEVELS = 15
atom_workspace_stack = [
    (0x16, "int_workspace_stack_low"),
    (0x25, "int_workspace_stack_mid1"),
    (0x34, "int_workspace_stack_mid2"),
    (0x43, "int_workspace_stack_high"),
]

# The hardware: {address: name}. The 8255 PPI at #B000 (port A: the
# keyboard row in bits 0-3 and the 6847's mode in bits 4-7; port B: the
# keyboard columns, with CTRL in bit 6 and SHIFT in bit 7; port C: the tape
# output, the 2.4 kHz tone, the speaker and the CSS out, the 2.4 kHz tone,
# tape input, REPT key and field sync in); the optional 6522 VIA at #B800
# (for a printer); and the ROM latch at #BFFF (with a ROM switching board).
_via_registers = ["register_b", "register_a", "ddrb", "ddra", "t1c_l", "t1c_h", "t1l_l", "t1l_h",
                  "t2c_l", "t2c_h", "sr", "acr", "pcr", "ifr", "ier", "register_a_no_handshake"]
atom_hardware = {
    0xb000: "ppi_port_a",
    0xb001: "ppi_port_b",
    0xb002: "ppi_port_c",
    0xb003: "ppi_control",
    **{0xb800 + i: "via_" + register for i, register in enumerate(_via_registers)},
    0xbfff: "rom_latch",
}

# What #B000 (the 8255's port A) selects: the 6847's mode in bits 4-7 (bit 4
# is A/G, graphics rather than text; bits 5-7 are GM0-GM2), and the keyboard
# row to read at #B001 in bits 0-3. The graphics modes, by bits 5-7, when bit
# 4 is set: CLEAR 1 to 4 write #30, #70, #B0 and #F0 (the 2-colour modes,
# from the kernel's table at #F6DD), and the others are the 6847's 4-colour
# modes, 1a to 4a (#10, #50, #90 and #D0: the floating point ROM's COLOUR
# selects the one that goes with the 2-colour mode). (With bit 4 clear, it's
# text mode, as CLEAR 0 writes #00.)
atom_graphics_modes = {
    0: "graphics mode 1a (64x64, 4 colours)",
    1: "graphics mode 1 (128x64, 2 colours)",
    2: "graphics mode 2a (128x64, 4 colours)",
    3: "graphics mode 2 (128x96, 2 colours)",
    4: "graphics mode 3a (128x96, 4 colours)",
    5: "graphics mode 3 (128x192, 2 colours)",
    6: "graphics mode 4a (128x192, 4 colours)",
    7: "graphics mode 4 (256x192, 2 colours)",
}

# The output bits of #B002 (the 8255's port C, bits 0-3): {bit: (what
# setting it does, what clearing it does, what toggling it does)}. The
# speaker is toggled to make a sound; bit 3 is the 6847's CSS, which chooses
# the colour set (#B002 OR 8 is the other set).
atom_port_c_outputs = {
    0: ("Tape output high", "Tape output low", "Toggle the tape output"),
    1: ("Turn the 2.4 kHz tape tone on", "Turn the 2.4 kHz tape tone off", "Toggle the 2.4 kHz tape tone"),
    2: ("Speaker high", "Speaker low", "Toggle the speaker"),
    3: ("Select colour set 1", "Select colour set 0", "Toggle the colour set"),
}

# The input bits of #B001 (port B) and #B002 (port C) that the comments on
# tests name (each is clear when its key is pressed; the field sync is clear
# during the flyback). Bits 0-5 of #B001 are the keys in the keyboard row
# selected at #B000, one for each column.
atom_port_inputs = {
    0xb001: {**{bit: "keyboard column {0}".format(bit) for bit in range(6)}, 6: "the CTRL key", 7: "the SHIFT key"},
    0xb002: {4: "the 2.4 kHz tape tone input", 5: "the tape input", 6: "the REPT key", 7: "the field sync"},
}

# The regions of memory, to group the memory locations at the top of the
# output: (start, end, name). The 6502's vectors at #FFFA are named by the
# CPU.
atom_memory_regions = [
    (0x0000, 0x0100, "Zero page"),
    (0x0100, 0x0140, "Input buffer"),
    (0x0140, 0x0180, "String buffer"),
    (0x0180, 0x0200, "Stack"),
    (0x0200, 0x0220, "OS vectors"),
    (0x0220, 0x0400, "Workspace"),
    (0x0400, 0x2800, "Extension memory"),
    (0x2800, 0x8000, "User memory"),
    (0x8000, 0x9800, "Screen memory"),
    (0xa000, 0xb000, "Utility ROM"),
    (0xb000, 0xc000, "I/O"),
    (0xc000, 0xd000, "BASIC ROM"),
    (0xd000, 0xe000, "Floating point ROM"),
    (0xe000, 0xf000, "DOS ROM"),
    (0xf000, 0xffcb, "Kernel ROM"),
    (0xffcb, 0xfffa, "OS entry points"),
]
