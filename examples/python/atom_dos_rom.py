"""The Acorn Atom's DOS ROM (#E000-#EFFF), as a test on a real program, with
acorn.atom(). *DOS (the kernel's command table, see atom_kernel.py) jumps to
#E000, which resets the disc controller and replaces the vectors for the
file system calls and the command line with the DOS's own.

It traces the code from the vectors the DOS sets up, its command table (the
same format as the kernel's), and the vectors *VDU, *EXEC and *SPOOL set,
and classifies its tables. The disc controller is an Intel 8271 at #0A00.
The NMI routines that move each byte to or from the 8271 are copied to zero
page (#F2) to run, so they're disassembled there (with move()); and *VDU
can switch the output to a screen at #0400 driven by a 6845 CRTC at #0800,
with a keyboard routine whose source is left over at the end of the ROM.

(py8dis warns that the NMI handler's jump to #F2 isn't traced, since it
can't tell which of the two routines is there: each is traced from its own
entry point instead.)"""

from commands import *
import acorn

load(0xe000, "orig/atom_dos_rom.orig", "6502", "9627dfb5f8302db8dd5702dbf7c09f72")
acorn.atom()

# The hardware: the 8271 disc controller, and the 6845 CRTC that *VDU uses
io_range(0x0a00, 0x0a05)
label(0x0a00, "fdc_command_status")
label(0x0a01, "fdc_parameter_result")
label(0x0a02, "fdc_reset")
label(0x0a04, "fdc_data")
io_range(0x0800, 0x0802)
label(0x0800, "crtc_address")
label(0x0801, "crtc_data")

# *DOS, and the vectors it sets: OSCLI's, NMI's, and LODVEC to SHTVEC (copied
# from default_vectors)
entry(0xe000, "dos")
entry(0xe3e5, "dos_cli")
entry(0xe87b, "dos_nmi")
label(0xef2a, "default_vectors")
for i, name in enumerate(["dos_load", "dos_save", "dos_rdar", "dos_star", "dos_bget", "dos_bput", "dos_find", "dos_shut"]):
    code_ptr(0xef2a + 2 * i, label_name=name)

# The routines that print the string after the JSR, up to a byte with bit 7
# set or a zero, and carry on there (the second prints "DISK " first)
hook_subroutine(0xe016, "print_inline_string", stringhiz_hook)
hook_subroutine(0xe00d, "print_disk_and_inline_string", stringhiz_hook)

# The command table: each command's name, then its routine's address, high
# byte first (the high byte has bit 7 set, which ends the name); an empty
# name ends the table
def command_table(table, prefix, names):
    """Mark the command table at 'table', naming each routine prefix + the
    command in lower case (or from 'names', {command: name})."""
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

label(0xe36c, "command_table")
expr_label(0xe36d, "command_table+1")
command_table(0xe36c, "star_", {"": "unknown_command"})
comment(0xe4c5, "A command that isn't in the table: look for a file of that name (COMMAND? if there isn't one)", indent=1, align=Align.AFTER_LABEL)

# The 8271: sending commands and parameters, and reading results
entry(0xe7d2, "fdc_command")            # (with the drive select bits for the current drive)
label(0xe7db, "fdc_write_command")
label(0xe7e4, "fdc_read_result")
entry(0xe809, "fdc_write_parameter")
entry(0xe7ed, "fdc_transfer")
comment(0xe7ed, "Send command A, then the track (#EC), the sector (#ED) and the number of sectors (#F1, of 256 bytes), and return to the caller's caller: the code after the JSR runs when the command is done (dos_nmi jumps through #D5)", indent=1, align=Align.AFTER_LABEL)
entry(0xe7a4, "check_fdc_result")       # (retrying, or giving the error DISK PROT, DISK ? or DISK ERROR)
entry(0xe75b, "select_drive")
label(0xe226, "wait_for_fdc")           # (until it isn't busy)
entry(0xe77a, "read_drive_status")

# The commands the DOS sends when it starts (four, from the start), and to
# seek the catalogue: each command and its parameters, then #EA
label(0xe862, "fdc_initialisation")
for addr, length, text in (
        (0xe862, 6, "Specify the initialisation: the step rate (#14), the head settling time (#05), and the head load and unload times (#CA)"),
        (0xe868, 6, "Specify the bad tracks for surface 0 (none), and the current track (0)"),
        (0xe86e, 6, "Specify the bad tracks for surface 1 (none), and the current track (0)"),
        (0xe874, 4, "Write the special register #17 (the mode register): #C1 (non-DMA mode)"),
        (0xe878, 3, "Seek track 0")):
    byte(addr, length)
    comment(addr, text, indent=1)
entry(0xe713, "fdc_send_commands")
comment(0xe713, "Send the command at fdc_initialisation+Y, and its parameters", indent=1, align=Align.AFTER_LABEL)

# Reading and writing the catalogue (track 0, sectors 0 and 1, to #2000):
# the seek sets the NMI handler (#D5) to seek_done
entry(0xe6ff, "seek_catalogue")
entry(0xe729, "seek_done")
expr(0xe70c, make_lo("seek_done"))
expr(0xe710, make_hi("seek_done"))
entry(0xe731, "read_catalogue")
label(0xe223, "read_catalogue_and_wait")
entry(0xe74a, "write_catalogue")

# The 8271's drive control output port for drives 0-3 (written by
# select_drive): bit 6 or 7 selects drive 0 or 1, bit 5 the side (drives 2
# and 3 are the other sides of 0 and 1), and bit 3 loads the head
label(0xe78e, "drive_control_bits")
byte(0xe78e, 4)

# The NMI routines: dos_nmi increments the address in the instruction at #F5
# (nmi_buffer_address) and jumps to #F2, for each byte. One of these two is
# copied to #F2, from nmi_routines (the read routine's last three bytes are
# the write routine's first): to read a byte into the buffer, or to write one
# from it. (The copy resets the address to #1FFF, i.e. #2000, the catalogue,
# after the first increment.)
label(0xe84f, "nmi_routines")
entry(0xe792, "copy_nmi_read_byte")
entry(0xe796, "copy_nmi_write_byte")
move_read = move(0xf2, 0xe84f, 8)
move_write = move(0xf2, 0xe857, 11)
with move_read:
    entry(0xf2, "nmi_read_byte")
with move_write:
    entry(0xf2, "nmi_write_byte")
label(0xf6, "nmi_buffer_address")
# (#F2 is either routine, depending on which was copied)
label(0xf2, "nmi_transfer_byte")
expr(0xe889, "nmi_transfer_byte")

# The routines *EXEC and *SPOOL put in RDCVEC and WRCVEC (they read the
# characters from the file, and write them to it, as well as the screen)
entry(0xe533, "exec_rdch")
entry(0xe559, "spool_wrch")

# *VDU sets WRCVEC and RDCVEC to the kernel's routines, or to the ones for a
# screen at #0400 (40 by 25) driven by a 6845 CRTC at #0800
label(0xe6f7, "vdu_vectors")
for addr, name in ((0xe6f7, None), (0xe6f9, None), (0xe6fb, "vdu_wrch"), (0xe6fd, "vdu_rdch")):
    code_ptr(addr, label_name=name)
label(0xef1c, "crtc_registers")
byte(0xef1c, 14)
comment(0xef1c, "The 6845's registers R0-R13 (40 by 25 characters, with the screen at #0400)", indent=1)

# vdu_rdch's handlers for the keys, as for the kernel's OSRDCH (see
# atom_kernel.py), but with its own for the cursor keys and COPY. The kernel
# finds the key with X from 11, so the tables are read 11 bytes before them.
label(0xed53, "vdu_rdch_handlers_low")
label(0xed60, "vdu_rdch_handlers_high")
for i, name in enumerate(["rdch_space_or_zero", "rdch_keys_1_to_4", "rdch_lock", "vdu_rdch_cursor", "rdch_keys_8_to_13",
                          "vdu_rdch_copy", "rdch_delete", "rdch_space_or_zero", "rdch_digits", "rdch_keys_28_to_31",
                          "rdch_at", "rdch_letters", "rdch_keys_59_to_63"]):
    code_ptr(0xed53 + i, 0xed60 + i, label_name=name)
expr(0xed46, "vdu_rdch_handlers_low-11")
expr(0xed4b, "vdu_rdch_handlers_high-11")
# Nothing jumps to these: each writes a cursor key's control code (up, left,
# right and down) to the screen, then reads another key
for addr in (0xed6d, 0xed71, 0xed75, 0xed79):
    entry(addr)
comment(0xed6d, "Not used: write a cursor key's control code to the screen (11, 8, 9 or 10), then read another key", indent=1)

# Left over at the end of the ROM, and not used: the end of a line, then
# lines of the assembler source of vdu_rdch (KBIN, at #ED22), each a line
# number (in BCD), the text and a CR
label(0xef3a, "unused")
comment(0xef3a, "Not used: left over from the assembler source of vdu_rdch (each line a line number in BCD, the text and a CR)", indent=1)
string(0xef3a, 5)
byte(0xef3f)
addr = 0xef40
while memory[addr] != 0 or memory[addr + 1] != 0:
    byte(addr, 2)
    end = addr + 2
    while memory[end] != 0x0d:
        end += 1
    string(addr + 2, end - addr - 2)
    byte(end)
    addr = end + 1
byte(addr, 0xf000 - addr)

go()
