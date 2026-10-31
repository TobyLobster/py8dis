"""BBC BASIC (Z80) for CP/M, by R.T. Russell (see orig/bbcbasic/README.txt),
a test of the Z80 on a large program. Its labels are from the map file
z88dk-z80asm made when it was built (orig/bbcbasic/bbcbasic.map)."""

from commands import *

load(0x0100, "orig/bbcbasic.orig", "z80", "78fde24b36c65ab407df934fd8da3004")

# CP/M
label(0x0000, "warm_boot")
label(0x0005, "bdos")

# The labels from the map file: each line is 'NAME = $ADDR ; addr, ...,
# module, ...' (a constant is 'const'). A name that's in more than one module
# (they're local to each) gets the module's name added, e.g. 'abs_eval' and
# 'abs_fpp'.
def map_labels(filename):
    labels = []
    for line in open(filename):
        name, rest = line.split("=", 1)
        value, info = rest.split(";", 1)
        info = [x.strip() for x in info.split(",")]
        if info[0] == "addr":
            labels.append((name.strip().lower(), int(value.strip()[1:], 16), info[3]))
    counts = {}
    for name, _, _ in labels:
        counts[name] = counts.get(name, 0) + 1
    return [(name + "_" + module if counts[name] > 1 else name, addr) for name, addr, module in labels]

for name, addr in map_labels("orig/bbcbasic/bbcbasic.map"):
    if 0x0100 <= addr < 0x3f00:
        label(addr, name)
    else:
        optional_label(addr, name)

entry(0x0100)

# The jump table after START, for the routines other code calls (WARM,
# ESCAPE, EXTERR, TELL, TEXT, SETTOP, CLEAR, RUN0, OSCLI, OSBGET, OSBPUT,
# OSSTAT and OSSHUT)
for i in range(13):
    entry(0x0103 + 3 * i)

# TELL prints the text after the call (ending with a zero), and returns
# after it; EXTERR reports the error whose text follows the call, and
# doesn't return
hook_subroutine(0x0d55, "tell", stringz_hook)
def exterr_hook(target, addr):
    stringz(addr + 3)
    return None
hook_subroutine(0x081a, "exterr", exterr_hook)

# POLY evaluates a polynomial whose coefficients follow the call, five bytes
# each (the mantissa's four bytes, then the exponent), up to one that's 1 or
# more (its exponent has bit 7 set), which it returns to: so that one is run
# as code (and is made of harmless instructions, e.g. 0, 0, 0, 0, &80: four
# NOPs and ADD A,B)
def poly_hook(target, addr):
    addr += 3
    while get_u8_runtime(addr + 4) < 0x80:
        byte(addr, 5)
        comment(addr, "coefficient", inline=True)
        addr += 5
    comment(addr, "(the last coefficient, run as code)", inline=True)
    return addr
hook_subroutine(0x3090, "poly", poly_hook)

# The tables of routines: the functions (FUNTBL), the string comparisons
# (SOPTBL), the statements (CMDTAB), and the floating point package's
# integer, function and floating point operations (DTABLE, FTABLE and
# RTABLE)
for addr, n in ((0x1e30, 57), (0x1ea2, 6), (0x0d5b, 58), (0x25fd, 16), (0x261d, 26), (0x2651, 16)):
    for i in range(n):
        code_ptr(addr + 2 * i)

# Code whose address is pushed, to return to after a USR call ('ld
# hl,usr2'), and a routine that isn't called (eval's SFLOAT: the floating
# point package has its own)
expr(0x1633, entry(get_u16_binary(0x1633)))
entry(0x2269)

# The * commands (COMDS): each name, ending with a character with bit 7 set,
# then its routine's address, until &FF
def with_terminator(c):
    return True
addr = 0x3928
while get_u8_runtime(addr) != 0xff:
    addr = stringhi(addr, with_terminator)
    code_ptr(addr)
    addr += 2
byte(addr)

go()
