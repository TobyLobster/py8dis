"""Make py8dis/commodoresource.py: the labels in Commodore's source for the
C64's, VIC-20's, C128's and Plus/4's ROMs, and the C128's and Plus/4's
workspace (the RAM locations their source declares), from the listings made
by assembling that source.

The source is in https://github.com/mist64/cbmsrc, whose build.sh assembles
it (with Commodore's own assembler under https://github.com/mist64/kernalemu
for the C64 and VIC-20, and https://github.com/mist64/cbm6502asm for the
others), making build/<directory>.lst for each. Then:

    python3 tools/make_commodoresource.py cbmsrc/build py8dis/commodoresource.py

It reads the listings named in ROM_LISTINGS and WORKSPACE_LISTINGS below.
They assemble to the real ROMs (checked against VICE's ROM images):
- C64: Kernal 901227-03 and BASIC 901226-01, to within one byte each.
- VIC-20: BASIC 901486-01 exactly. Kernal 901486-06 (NTSC) and 901486-07
  (PAL), apart from small patches and the PAL timing values, with the code at
  the same addresses; its patch area at &e4cf-&e4ff holds different code in
  those ROMs, so labels there are left out.
- C128: BASIC, the screen editor and the monitor (318018-04, 318019-04,
  318020-05) exactly. The Kernal source is the 1988 revision, 318020-06, which
  differs from 318020-05 in a few bytes and its patch at &cf9e-&cfff (left
  out).
- Plus/4: BASIC 318006-01 to within 6 bytes, and Kernal 318004-05 to within
  39 bytes (single bytes, and a patch at &cfc5-&cfe9, left out).

Labels: one is taken from each line of a listing that has one, an
instruction or data line with a label (the address is the assembler's), or a
label alone on a line. Where an address has more than one, an instruction's
or data's label is preferred to one alone on a line (e.g. RESTOR rather than
TBLA0E, the end of the table before it), then the first. Only labels in each
ROM's ranges are taken (not the workspace, constants or local labels).

Workspace: each 'name *=*+n' declaration in the RAM ranges, with its size
from the assembler's location counter. Where several listings or names
declare an address, the first listing's first name is taken (the others are
other uses of the same bytes), and each location stops where the next one
starts. A name that another listing gives to a different address gets that
listing's suffix (e.g. 'count_monitor').
"""

import collections
import os
import re
import sys

MNEMONICS = set("adc and asl bcc bcs beq bit bmi bne bpl brk bvc bvs clc cld cli clv cmp cpx cpy dec dex dey eor inc inx iny "
                "jmp jsr lda ldx ldy lsr nop ora pha php pla plp rol ror rti rts sbc sec sed sei sta stx sty tax tay tsx txa txs tya".split())

# The two listing formats: Commodore's assembler under kernalemu (the C64 and
# VIC-20), e.g. '00344  E50A  B0 07       PLOT   BCS PLOT10'; and cbm6502asm,
# e.g. '     E00C   BD E04B      2375   10$\tlda mmutbl,x'
KERNALEMU_LINE = re.compile(r"^\d{5}  ([0-9A-F]{4})  (.{12})(.*)$")
CBM6502ASM_LINE = re.compile(r"^.{5}([0-9A-F]{4})   (.{12}) *\d+   (.*)$")

def listing_lines(path):
    """[(address, code, source)] for the listing's lines with an address"""
    text = open(path, errors="replace").read().replace("\r\n", "\n").replace("\r", "\n")
    result = []
    for line in text.split("\n"):
        m = KERNALEMU_LINE.match(line) or CBM6502ASM_LINE.match(line)
        if m:
            result.append((int(m.group(1), 16), m.group(2).strip(), m.group(3)))
    return result

# The ROMs: (variable in the module, listing, what it is, ranges of addresses
# to take labels from, ranges to leave out)
ROM_LISTINGS = [
    ("c64_kernal_rom_labels",    "KERNAL_C64_03.lst",  "the C64's Kernal ROM (901227-03)",            [(0xe000, 0x10000)], []),
    ("c64_basic_rom_labels",     "BASIC_C64.lst",      "the C64's BASIC ROM (901226-01, &a000-&bfff and &e000-&e4d2)", [(0xa000, 0xc000), (0xe000, 0xe4d3)], []),
    ("vic20_kernal_rom_labels",  "KERNAL_VIC_04.lst",  "the VIC-20's Kernal ROM (901486-06 and -07)", [(0xe000, 0x10000)], [(0xe4cf, 0xe500)]),
    ("vic20_basic_rom_labels",   "BASIC_VIC.lst",      "the VIC-20's BASIC ROM (901486-01, &c000-&dfff and &e000-&e47b)", [(0xc000, 0xe47c)], []),
    ("c128_kernal_rom_labels",   "KERNAL_C128_06.lst", "the C128's Kernal (in 318020-05, &e000-&ffff, and its patches at &cf80)", [(0xcf80, 0xd000), (0xe000, 0x10000)], [(0xcf9e, 0xd000)]),
    ("c128_editor_rom_labels",   "EDITOR_C128.lst",    "the C128's screen editor (in 318020-05, &c000-&cfff)", [(0xc000, 0xd000)], []),
    ("c128_monitor_rom_labels",  "MONITOR_C128.lst",   "the C128's monitor (in 318019-04, &b000-&bfff)", [(0xb000, 0xc000)], []),
    ("c128_basic_rom_labels",    "BASIC_C128_04.lst",  "the C128's BASIC 7.0 (318018-04 and 318019-04, &4000-&afff)", [(0x4000, 0xb000)], []),
    ("plus4_kernal_rom_labels",  "KERNAL_TED_05.lst",  "the Plus/4's Kernal (318004-05, &c000-&ffff)", [(0xc000, 0x10000)], [(0xcfc5, 0xcfea)]),
    ("plus4_basic_rom_labels",   "BASIC_TED.lst",      "the Plus/4's BASIC 3.5 (318006-01, &8000-&bfff, and parts of the Kernal ROM)", [(0x8000, 0x10000)], []),
]

# The workspace: (variable, listings in order of preference with the suffix
# for each, what it is, ranges)
WORKSPACE_LISTINGS = [
    ("c128_workspace", [("KERNAL_C128_06.lst", ""), ("EDITOR_C128.lst", "_editor"), ("BASIC_C128_04.lst", "_basic"), ("MONITOR_C128.lst", "_monitor")],
     "the C128's workspace", [(0x0000, 0x0100), (0x0200, 0x1400)]),
    ("plus4_workspace", [("KERNAL_TED_05.lst", ""), ("BASIC_TED.lst", "_basic")],
     "the Plus/4's workspace", [(0x0000, 0x0100), (0x0200, 0x0800)]),
]

def rom_labels(path, ranges, excluded):
    """{address: name} for the labels in the listing"""
    candidates = collections.defaultdict(list)
    for addr, code, source in listing_lines(path):
        if source[:1] in ("\t", " ", ";", ".", "*"):
            continue
        tokens = source.split(";")[0].split()
        if not tokens or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]) or tokens[0].lower() in MNEMONICS:
            continue
        if len(tokens) > 1 and (tokens[1].startswith("=") or tokens[1].startswith("*=")):
            continue
        if not any(lo <= addr < hi for lo, hi in ranges) or any(lo <= addr < hi for lo, hi in excluded):
            continue
        alone = len(tokens) == 1
        candidates[addr].append((1 if alone else 0, tokens[0].lower()))
    labels = {}
    for addr, names in candidates.items():
        names.sort(key=lambda n: n[0])     # (stable, so the first of each kind)
        labels[addr] = names[0][1]
    duplicates = [n for n, c in collections.Counter(labels.values()).items() if c > 1]
    assert not duplicates, duplicates
    return labels

def workspace(build_dir, listings, ranges):
    """[(address, size, name)] for the workspace declared in the listings"""
    declared = {}           # address -> (name, size)
    names = {}              # name -> address
    for listing, suffix in listings:
        for addr, code, source in listing_lines(os.path.join(build_dir, listing)):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+\*\s*=\s*\*\s*\+", source)
            if not m or not code.startswith("=") or not any(lo <= addr < hi for lo, hi in ranges):
                continue
            name = m.group(1).lower()
            size = int(code[1:], 16) - addr
            if addr in declared or size <= 0:
                continue
            if name in names:
                if names[name] == addr:
                    continue
                name += suffix
                assert name not in names, name
            declared[addr] = (name, size)
            names[name] = addr
    result = []
    addrs = sorted(declared)
    for i, addr in enumerate(addrs):
        name, size = declared[addr]
        if i + 1 < len(addrs):
            size = min(size, addrs[i + 1] - addr)
        result.append((addr, size, name))
    return result

def main():
    build_dir, out = sys.argv[1], sys.argv[2]
    with open(out, "w") as f:
        f.write('''"""
Names from Commodore's source for its machines' ROMs (made by
tools/make_commodoresource.py, from the listings made by assembling the
source in https://github.com/mist64/cbmsrc, which assemble to the real ROMs):

- the labels in the C64's, VIC-20's, C128's and Plus/4's Kernal and BASIC
  ROMs (and the C128's screen editor and monitor), as {address: name}, which
  commodore.c64() etc. give as optional labels (see their rom_labels);
- the C128's and Plus/4's workspace, as [(address, size, name)].
"""
''')
        for variable, listing, description, ranges, excluded in ROM_LISTINGS:
            labels = rom_labels(os.path.join(build_dir, listing), ranges, excluded)
            f.write("\n# %s: %d labels\n%s = {\n" % (description[0].upper() + description[1:], len(labels), variable))
            for addr in sorted(labels):
                f.write("    0x%04x: %r,\n" % (addr, labels[addr]))
            f.write("}\n")
            print("%s: %d labels" % (variable, len(labels)))
        for variable, listings, description, ranges in WORKSPACE_LISTINGS:
            locations = workspace(build_dir, listings, ranges)
            f.write("\n# %s: %d locations\n%s = [\n" % (description[0].upper() + description[1:], len(locations), variable))
            for addr, size, name in locations:
                f.write("    (0x%04x, %d, %r),\n" % (addr, size, name))
            f.write("]\n")
            print("%s: %d locations" % (variable, len(locations)))

if __name__ == "__main__":
    main()
