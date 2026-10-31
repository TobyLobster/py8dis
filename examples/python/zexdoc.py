"""ZEXDOC, Frank Cringle's Z80 instruction exerciser for CP/M (see
orig/zexdoc/README.txt), a test of the Z80 on a program that is mostly tables:
each test is a 96 byte descriptor of an instruction to try, the machine states
to try it with and the CRC expected. Its labels are from the symbol file pasmo
made when it was rebuilt (orig/zexdoc/zexdoc.sym)."""

from commands import *

load(0x0100, "orig/zexdoc.orig", "z80", "be3691b6b910d2c2e05e194cd529e45c")

# CP/M (the program's own 'bdos' routine saves the registers and calls this)
label(0x0000, "warm_boot")
label(0x0005, "cpm_bdos")

# The labels from the symbol file: each line is 'name EQU 0xxxxH'
names = {}
for line in open("orig/zexdoc/zexdoc.sym"):
    name, _, value = line.split()
    names[int(value[:-1], 16)] = name
    label(int(value[:-1], 16), name)

entry(0x0100)

# Called only by debugging code that isn't assembled
entry(addr("hexstr"))

# The instruction under test is copied to 'iut' (4 bytes, padded with
# nops) and run there, and 'test' sets the flags it checks by changing the
# operand of the 'and' at 'flgmsk'
byte(addr("iut"), 4)
comment(addr("iut"), "The instruction under test (self-modified code)", inline=True)
entry(addr("iut") + 4)
expr(0x1b37, make_add("iut", 1))
comment(addr("flgmsk"), "The operand is the flag mask (self-modified code)", inline=True)
expr(0x1ae9, make_add("flgmsk", 1))

# The top of the memory for programs is the address of CP/M's BDOS
expr(0x0114, make_add("cpm_bdos", 1))

# The 'ld de,nnnn', 'ld hl,nnnn' and 'ld sp,nnnn' instructions that load the
# address of the program's data or messages
for instruction in (0x0117, 0x011f, 0x012f, 0x1af1, 0x1afd, 0x1b03, 0x1b0a, 0x1b12,
              0x1b4f, 0x1b55, 0x1b60, 0x1b68, 0x1b6e, 0x1b83, 0x1b89, 0x1b93,
              0x1b9b, 0x1bf9, 0x1c1d, 0x1c8c, 0x1cb0, 0x1d4a, 0x1d60, 0x1d69,
              0x1d6c, 0x1e35, 0x1e59, 0x1e74):
    expr(instruction + 1, names[get_u16_runtime(instruction + 1)])
expr(0x1d34, make_add("msbt", 2))

msbt = addr("msbt")

# The machine state before a test is at msbt (a 2 byte memory operand, then
# IY, IX, HL, DE, BC, F, A and SP), so the tests' instructions and registers
# use addresses near it
def msbt_expr(addr):
    value = get_u16_runtime(addr)
    if value == msbt:
        expr(addr, "msbt")
    elif msbt - 1 <= value <= msbt + 17:
        if value < msbt:
            expr(addr, make_subtract("msbt", msbt - value))
        else:
            expr(addr, make_add("msbt", value - msbt))

# A machine state: the instruction under test (4 bytes), then the memory
# operand, IY, IX, HL, DE, BC (words), F, A (bytes) and SP (a word)
def machine_state(addr, with_addresses):
    byte(addr, 4, cols=4)
    word(addr + 4, 6, cols=6)
    byte(addr + 16, 2, cols=2)
    word(addr + 18)
    if with_addresses:
        for i in range(1, 3):
            if get_u16_runtime(addr + i) == msbt:
                expr(addr + i, make_lo("msbt"))
                expr(addr + i + 1, make_hi("msbt"))
        for i in range(6):
            msbt_expr(addr + 4 + 2 * i)
        msbt_expr(addr + 18)

# Each test's descriptor: a flag mask (the flags to check), the machine state
# to start with, the bits of it to try every combination of ('incmask'), the
# bits to try one at a time ('shiftmask'), the CRC expected (4 bytes) and the
# test's name ending with '$'
def descriptor(addr):
    byte(addr)
    machine_state(addr + 1, True)
    machine_state(addr + 21, False)
    machine_state(addr + 41, False)
    byte(addr + 61, 4)
    stringterm(addr + 65, ord("$"))

# The list of tests, ending with 0
ptr = addr("tests")
while get_u16_runtime(ptr) != 0:
    word(ptr)
    expr(ptr, names[get_u16_runtime(ptr)])
    descriptor(get_u16_runtime(ptr))
    ptr += 2
word(ptr)

# The text the program prints, each ending with '$'
for name in ("msg1", "msg2", "okmsg", "ermsg1", "ermsg2", "crlf"):
    stringterm(addr(name), ord("$"))

# The table for the CRC (256 entries, high byte first)
byte(addr("crctab"), 1024, cols=4)

# The rest of the last 128 byte CP/M record (whatever was in memory)
byte(0x2289, 0x2300 - 0x2289)

go()
