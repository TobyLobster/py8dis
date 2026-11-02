"""The BBC Micro's MOS 1.20, its operating system ROM (&c000-&ffff), as a test
on a large real program, with acorn.bbc(). Most of the code is only reached
through tables of addresses (the default vectors, OSBYTE, OSWORD and VDU,
and the routines for plotting lines), so the control file reads each table
with get_u16_binary() or get_u8_binary(), traces each routine with entry()
and names it, and writes the table's entries as those names with expr().
The character set at the start is shown in picture binary, and the text
hidden under the I/O area at &fc00 as a string."""

from commands import *
import acorn

# Load the program to be disassembled into py8dis's memory.
# The md5sum is optional but helps avoid confusion if there are
# multiple versions of the same program.
load(0xc000, "orig/os12.orig", "6502")

# Add labels specific to the BBC Micro
acorn.bbc()

# Entry points
entry(0xdc1c)
entry(0xd9cd)

# default vector addresses
for i in range(0xd940, 0xd976, 2):
    addr = get_u16_binary(i)
    entry(addr)

# OSBYTE 0-21
n=0
for i in range(0xe5b3, 0xe5df, 2):
    addr = get_u16_binary(i)
    name = "osbyte{0}EntryPoint".format(n)
    entry(addr, name)
    word(i)
    expr(i, name)
    n += 1

# OSBYTE 117-160
n=117
for i in range(0xe5df, 0xe637, 2):
    addr = get_u16_binary(i)
    name = "osbyte{0}EntryPoint".format(n)
    entry(addr, name)
    word(i)
    expr(i, name)
    n += 1

# OSBYTE 166-255
entry(0xe99c, "osbyte166to255EntryPoint")
word(0xe637)
expr(0xe637, "osbyte166to255EntryPoint")
# (Then the address of a routine that jumps through USERV)
word(0xe639)
expr(0xe639, "uservJumper")

entry(0xe659, "uservJumper")

# OSWORD 0-13
n=0
for i in range(0xe63b, 0xe657, 2):
    addr = get_u16_binary(i)
    name = "osword{0}EntryPoint".format(n)
    entry(addr, name)
    word(i)
    expr(i, name)
    n += 1

# VDU 0-31 and 127 routines: the low bytes of their addresses are at &c333,
# and the high bytes at &c354. A high byte with bit 7 clear isn't the
# address's high byte: its top four bits are the page above &c300 (and its
# bottom four bits aren't part of the address).
n=0
for i in range(0,33):
    low_addr = 0xc333 + i
    high_addr = 0xc354 + i
    low = get_u8_binary(low_addr)
    high = get_u8_binary(high_addr)
    if (high & 128):
        addr = (high * 256) + low
    else:
        high = high // 16
        addr = (high*256 + 0xc300) + low
    if n == 32:
        n = 127
    name = "vdu{0}EntryPoint".format(n)
    entry(addr, name)
    n += 1

entry(0xcc02, "clearScreenRoutineEntryPointMODE012")
label(0xcc32, "clearScreenRoutineEntryPointMODE3")
label(0xcc7a, "clearScreenRoutineEntryPointMODE45")
label(0xcc92, "clearScreenRoutineEntryPointMODE6")
label(0xcce6, "clearScreenRoutineEntryPointMODE7")

# Four routines for plotting lines, with the low bytes of their addresses at
# &c4ae and the high bytes at &c4b2
n=0
for i in range(0, 4):
    low_addr = 0xc4ae + i
    high_addr = 0xc4b2 + i
    byte(low_addr)
    byte(high_addr)

    low = get_u8_binary(low_addr)
    high = get_u8_binary(high_addr)
    addr = (high * 256) + low

    name = "plotLine{0}".format(i)
    entry(addr, name)
    expr(low_addr, "<{0}".format(name))
    expr(high_addr, ">{0}".format(name))


# Output initial section as bytes, in picture binary format (the character
# set, 8 bytes for each character, one byte to a line)
byte(0xc000, 0x300, cols=1)
picture_binary(0xc000, 0x300)
label(0xd952, "ld952")

# The ROM's bytes at &fc00 can't be read on the machine, since the I/O is
# there; they're text
string(0xfc00, 0xfefe-0xfc00)

# The OS calls that aren't called from the ROM itself, named as acorn.bbc()
# names them (in capitals, unless config.set_upper_case_os_calls(False))
entry(0xffb9, acorn.os_call_name("osrdsc"))
entry(0xffbc, acorn.os_call_name("vduchr"))
entry(0xffbf, acorn.os_call_name("oseven"))
entry(0xffc8, acorn.os_call_name("nvrdch"))
entry(0xffcb, acorn.os_call_name("nvwrch"))
entry(0xffd1, acorn.os_call_name("osgbpb"))
entry(0xffda, acorn.os_call_name("osargs"))
entry(0xffdd, acorn.os_call_name("osfile"))
entry(0xffec, acorn.os_call_name("oswrcr"))
entry(0xfff1, acorn.os_call_name("osword"))

entry(0xff51)

# Use all the information provided to actually disassemble the program.
go()
