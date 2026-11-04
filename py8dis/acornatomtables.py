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
    (0xfe66, "wait_for_flyback", "Wait for the start of the next field flyback", None),
    (0xfe6b, "wait_for_flyback_or_now", "Wait for the field flyback, unless it's under way", None),
    (0xfe71, "scan_keyboard", "Scan the keyboard: if a key is pressed, carry is clear and Y is its ASCII code minus 32", None),
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
