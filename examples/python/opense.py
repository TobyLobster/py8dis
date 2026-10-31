"""OpenSE BASIC 3.2.1 (see orig/opense/README.txt), an open source
replacement for the ZX Spectrum 48K ROM, a test of the Z80 on a ROM that is
like the Spectrum's but not the same, with spectrum.spectrum48() naming the
system variables and following RST $08 and RST $28. Its labels are from the
symbol file pasmo made when it was rebuilt (orig/opense/opense.sym)."""

from commands import *
import spectrum

load(0x0000, "orig/opense.orig", "z80", "17a4560020e02e5ea82b1eecc53f4282")

# (Not the names of the Spectrum ROM's routines, which are in other places)
spectrum.spectrum48(rom_labels=False)

# The labels from the symbol file: each line is 'name EQU 0xxxxH' (two are
# pasmo's local labels, e.g. 'x80_fcp.lz', written 'x80_fcp_lz' here)
for line in open("orig/opense/opense.sym"):
    name, _, value = line.split()
    label(int(value[:-1], 16), name.replace(".", "_"))

# The restarts and the NMI
for addr in range(0x0000, 0x0040, 8):
    entry(addr)
entry(0x0066)

# The tables of routines, many where the Spectrum ROM has them
spectrum.offset_table(0x0a11, 18)               # the control characters'
spectrum.offset_table(0x0fa0, 9)                # the editing keys'
for addr in range(0x15af, 0x15c3, 5):           # the initial channel information
    code_ptr(addr)                              # (output and input routines,
    code_ptr(addr + 2)                          # then the channel's letter)
    byte(addr + 4)
byte(0x15c3)                                    # (the end marker)
spectrum.keyed_offset_table(0x162d)             # the channels'
spectrum.keyed_offset_table(0x1649)             # for CLOSE
spectrum.keyed_offset_table(0x177a)             # for OPEN
# The commands' parameter tables: OpenSE BASIC has more commands, and its
# class $0C (like 6, a number, but then the end of the statement) is followed
# by the command's routine too
syntax_tables = set()
for i in range(56):
    table = spectrum.offset_entry(0x1a39 + i, code=False)
    if table not in syntax_tables:
        syntax_tables.add(table)
        spectrum.syntax_table(table, routine_classes=(0x00, 0x03, 0x05, 0x0c))
spectrum.offset_table(0x1c00, 13)               # the parameter classes'
spectrum.keyed_offset_table(0x2596)             # the scanning functions'
for i in range(66):                             # the calculator's
    code_ptr(0x32de + 2 * i)

# Code whose address is loaded into a register, to be pushed as a return
# address or stored as a channel's routine (each the address of an
# instruction's operand)
for operand_addr in (0x04c3, 0x055f, 0x0a61, 0x0a66, 0x0a6b, 0x0f31, 0x1109, 0x1131, 0x1566, 0x1b5b):
    expr(operand_addr, entry(get_u16_runtime(operand_addr)))

# Code the ROM doesn't use: an RST 0 after the start, and 'pop hl, ret' and
# a jump to report O where the Spectrum ROM has CLOSE-STR and CAT-ETC
for addr in (0x0007, 0x171c, 0x1793):
    entry(addr)

# GEN-ENT-1 and GEN-ENT-2 are followed by the calculator's bytecode, as in the
# Spectrum ROM, but at other addresses
hook_subroutine(0x3365, "gen_ent_1", spectrum.calculator_hook)
hook_subroutine(0x3369, "gen_ent_2", spectrum.calculator_hook)

# The tokens and messages, each ending with a character with bit 7 set (some
# after a byte with bit 7 set, so that the first is number 1)
spectrum.stringhi_list(0x00a9, 0x0239)          # the tokens
byte(0x1396)
spectrum.stringhi_list(0x1397, 0x13d5)          # the copyright message and "Start tape..."
spectrum.stringhi_list(0x13d5, 0x1403)          # the tape messages
spectrum.stringhi_list(0x1403, 0x1555)          # the error reports
byte(0x3235)
stringhi(0x3236, lambda c: True)                # "Scroll?"

# The key tables: the letters and digits, with symbol shift, in extended
# mode and in graphics mode
string(0x0239, 39)
string(0x0260, 10)
string(0x026a, 26)
string(0x0284, 10)

# The notes' frequencies for BEEP, C to B (5 byte floating point numbers)
for i, note in enumerate(("C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B")):
    byte(0x046e + 5 * i, 5)
    comment(0x046e + 5 * i, note, inline=True)

# The calculator's constants (5 byte floating point numbers): 0, 1, 1/2,
# pi/2 and 10
for i in range(5):
    byte(0x32c5 + 5 * i, 5)

# The two cursors, then the character set, $20 to $7F, 8 bytes each ($60 is
# the pound sign, and $7F the copyright sign)
for i in range(0x62):
    addr = 0x3cf0 + 8 * i
    picture_binary(addr, 8)
    byte(addr, 8, cols=1)
    if i >= 2:
        comment(addr, spectrum.character_description(0x20 + i - 2), inline=True)

go()
