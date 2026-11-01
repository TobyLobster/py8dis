"""
Make commodoresource.py

Makes py8dis/commodoresource.py: the labels in Commodore's source for the
C64's, VIC-20's, C128's, Plus/4's and PET's ROMs and the 1541's DOS ROM, and
the C128's, Plus/4's, PET's and 1541's workspace (the RAM locations their
source declares), from the listings made by assembling that source.
commodore.py names the ROMs' addresses with the labels (see
commodore.location_names()), and commodoretables.py makes the machines'
workspace locations from the workspace, adding descriptive names. py8dis
doesn't run this: it only uses the module this makes.

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
- PET (Martin Hoffmann-Vetter's reconstructions, BASIC_PET_V1R_REC,
  BASIC_PET_V2_REC, BASIC_PET_V4R_REC and KERNAL_PET_1.0_REC, 2.0_REC and
  4.0_REC, as VICE has them):
  - BASIC 1 (901439-09, -05, -02, -06), its editor 901439-03 and Kernal
    901439-04/-07 exactly, apart from unused bytes at their ends;
  - BASIC 2 (901465-01, -02), its editor 901447-24 and Kernal 901465-03
    likewise;
  - BASIC 4 (901465-23, -20, -21) and Kernal 901465-22 apart from three
    checksum bytes. Its source's editor (&e000-&e7ff) is 901447-29, which
    no PET in VICE has (each model's BASIC 4 editor is different), so it's
    left out.
  The European 80-column editor's source (EDITOR_PET_EURO) declares the
  80-column editor's workspace.
- 1541 (DOS_1541_05_REC and DOS_1541C_03_REC, built like the PET's): DOS
  325302-01 and 901229-05 apart from two checksum bytes, and the 1541-II's
  251968-03 apart from its copyright text at &c002-&c038 and two bytes. Their
  workspace (and the two VIAs, which the source declares in the same way) is
  the same.

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

# The 6502's mnemonics: a line that starts with one, rather than a label,
# has no label
MNEMONICS = set("adc and asl bcc bcs beq bit bmi bne bpl brk bvc bvs clc cld cli clv cmp cpx cpy dec dex dey eor inc inx iny "
                "jmp jsr lda ldx ldy lsr nop ora pha php pla plp rol ror rti rts sbc sec sed sei sta stx sty tax tay tsx txa txs tya".split())

# The two listing formats: Commodore's assembler under kernalemu (the C64 and
# VIC-20), e.g. '00344  E50A  B0 07       PLOT   BCS PLOT10'; and cbm6502asm,
# e.g. '     E00C   BD E04B      2375   10$\tlda mmutbl,x'. Each matches the
# address, the 12 columns of code (what's assembled, or for cbm6502asm '='
# and the location counter after a '*=*+n'), and the source line.
KERNALEMU_LINE = re.compile(r"^\d{5}  ([0-9A-F]{4})  (.{12})(.*)$")
CBM6502ASM_LINE = re.compile(r"^.{5}([0-9A-F]{4})   (.{12}) *\d+   (.*)$")

def listing_lines(path):
    """[(address, code, source)] for the listing's lines with an address, in
    either format: code is the code column, without the spaces around it
    (e.g. 'B0 07', or '' if there's none), and source is the source line.
    (The listing is read with any line ends, and undecodable bytes
    replaced.)"""
    text = open(path, errors="replace").read().replace("\r\n", "\n").replace("\r", "\n")
    result = []
    for line in text.split("\n"):
        m = KERNALEMU_LINE.match(line) or CBM6502ASM_LINE.match(line)
        if m:
            result.append((int(m.group(1), 16), m.group(2).strip(), m.group(3)))
    return result

# The ROMs: (variable in the module, listing, what it is (for the variable's
# comment in the module), ranges of addresses to take labels from, ranges to
# leave out)
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
    ("pet1_kernal_rom_labels",   "KERNAL_PET_1.0_REC.lst", "the PET's BASIC 1 Kernal and screen editor (901439-03, from &e1e1, and 901439-04/-07)", [(0xe1e1, 0xe800), (0xf000, 0x10000)], []),
    ("pet1_basic_rom_labels",    "BASIC_PET_V1R_REC.lst", "the PET's BASIC 1 (901439-09, -05, -02, -06, and 901439-03 to &e1e0)", [(0xc000, 0xe1e1)], []),
    ("pet2_kernal_rom_labels",   "KERNAL_PET_2.0_REC.lst", "the PET's BASIC 2 Kernal and screen editor (901447-24, from &e1de, and 901465-03)", [(0xe1de, 0xe800), (0xf000, 0x10000)], []),
    ("pet2_basic_rom_labels",    "BASIC_PET_V2_REC.lst", "the PET's BASIC 2 (901465-01, -02, and 901447-24 to &e1dd)", [(0xc000, 0xe1de)], []),
    ("pet4_kernal_rom_labels",   "KERNAL_PET_4.0_REC.lst", "the PET's BASIC 4 Kernal (901465-21 from &d472, and 901465-22; not the screen editor at &e000)", [(0xd472, 0xe000), (0xf000, 0x10000)], []),
    ("pet4_basic_rom_labels",    "BASIC_PET_V4R_REC.lst", "the PET's BASIC 4 (901465-23, -20, and 901465-21 to &d471)", [(0xb000, 0xd472)], []),
    ("drive1541_rom_labels",     "DOS_1541_05_REC.lst", "the 1541's DOS ROM (325302-01 and 901229-05)", [(0xc000, 0x10000)], []),
    ("drive1541ii_rom_labels",   "DOS_1541C_03_REC.lst", "the 1541-II's DOS ROM (251968-03)", [(0xc000, 0x10000)], []),
]

# The workspace: (variable, listings in order of preference with the suffix
# for each (added to a name another listing gives a different address),
# what it is, ranges of addresses to take declarations from)
WORKSPACE_LISTINGS = [
    ("c128_workspace", [("KERNAL_C128_06.lst", ""), ("EDITOR_C128.lst", "_editor"), ("BASIC_C128_04.lst", "_basic"), ("MONITOR_C128.lst", "_monitor")],
     "the C128's workspace", [(0x0000, 0x0100), (0x0200, 0x1400)]),
    ("plus4_workspace", [("KERNAL_TED_05.lst", ""), ("BASIC_TED.lst", "_basic")],
     "the Plus/4's workspace", [(0x0000, 0x0100), (0x0200, 0x0800)]),
    ("pet1_workspace", [("KERNAL_PET_1.0_REC.lst", ""), ("BASIC_PET_V1R_REC.lst", "_basic")],
     "the BASIC 1 PET's workspace", [(0x0000, 0x0100), (0x0200, 0x0400)]),
    ("pet2_workspace", [("KERNAL_PET_2.0_REC.lst", ""), ("BASIC_PET_V2_REC.lst", "_basic")],
     "the BASIC 2 PET's workspace", [(0x0000, 0x0100), (0x0200, 0x0400)]),
    ("pet4_workspace", [("KERNAL_PET_4.0_REC.lst", ""), ("BASIC_PET_V4R_REC.lst", "_basic")],
     "the BASIC 4 PET's workspace (40 columns)", [(0x0000, 0x0100), (0x0200, 0x0400)]),
    ("pet4_80_workspace", [("KERNAL_PET_4.0_REC.lst", ""), ("EDITOR_PET_EURO.lst", "_editor"), ("BASIC_PET_V4R_REC.lst", "_basic")],
     "the BASIC 4 PET's workspace (80 columns, with the 80-column editor's)", [(0x0000, 0x0100), (0x0200, 0x0400)]),
    ("drive1541_workspace", [("DOS_1541_05_REC.lst", "")],
     "the 1541's workspace, and its VIAs", [(0x0000, 0x0800), (0x1800, 0x1810), (0x1c00, 0x1c10)]),
]

def rom_labels(path, ranges, excluded):
    """{address: name} for the labels in the listing at path, at the
    addresses in the ranges and not in the excluded ranges (each [(start,
    end)], end exclusive), as the module docstring describes. Names are in
    lower case. A name at two addresses stops it with an assertion."""
    # The labels found at each address: [(1 for a label alone on a line, 0
    # for one on an instruction or data, name)], in the listing's order
    candidates = collections.defaultdict(list)
    for addr, code, source in listing_lines(path):
        # (A label starts the line: a line starting with a space, a tab,
        # ';', '.' or '*' has none)
        if source[:1] in ("\t", " ", ";", ".", "*"):
            continue
        tokens = source.split(";")[0].split()
        # (Not a local label, e.g. '10$', or an instruction)
        if not tokens or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]) or tokens[0].lower() in MNEMONICS:
            continue
        # (Not a constant, 'NAME = value', or a workspace declaration, 'NAME
        # *=*+n')
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
    """[(address, size, name)] for the workspace declared in the listings
    (in build_dir, [(listing, suffix)] in order of preference), in address
    order: each 'name *=*+n' declaration at an address in the ranges, as the
    module docstring describes. Names are in lower case."""
    declared = {}           # address -> (name, size)
    names = {}              # name -> address
    for listing, suffix in listings:
        lines = listing_lines(os.path.join(build_dir, listing))
        for i, (addr, code, source) in enumerate(lines):
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+\*\s*=\s*\*\s*\+", source)
            if not m or not any(lo <= addr < hi for lo, hi in ranges):
                continue
            if code.startswith("="):
                # (cbm6502asm gives the location counter after it)
                size = int(code[1:], 16) - addr
            elif not code and i + 1 < len(lines):
                # (Commodore's assembler doesn't, but the next line has it)
                size = lines[i + 1][0] - addr
            else:
                continue
            name = m.group(1).lower()
            # (The first declaration of an address is taken; a name declared
            # again at the same address is skipped, and at another address,
            # gets the listing's suffix)
            if addr in declared or size <= 0:
                continue
            if name in names:
                if names[name] == addr:
                    continue
                name += suffix
                assert name not in names, name
            declared[addr] = (name, size)
            names[name] = addr
    # Each location stops where the next one starts
    result = []
    addrs = sorted(declared)
    for i, addr in enumerate(addrs):
        name, size = declared[addr]
        if i + 1 < len(addrs):
            size = min(size, addrs[i + 1] - addr)
        result.append((addr, size, name))
    return result

def main():
    """Read the listings in the build directory (the first argument) and
    write the module (the second): its docstring, then for each ROM a dict
    {address: name} and for each workspace a list [(address, size, name)],
    each with a comment saying what it is and how many there are. The
    counts are printed too."""
    build_dir, out = sys.argv[1], sys.argv[2]
    with open(out, "w") as f:
        f.write('''"""
Names from Commodore's source for its machines' ROMs (made by
tools/make_commodoresource.py, from the listings made by assembling the
source in https://github.com/mist64/cbmsrc, which assemble to the real ROMs):

- the labels in the C64's, VIC-20's, C128's, Plus/4's and PET's Kernal and
  BASIC ROMs (and the C128's screen editor and monitor) and the 1541's DOS
  ROM, as {address: name}, which commodore.c64() etc. give as optional
  labels (see their rom_labels);
- the C128's, Plus/4's, PET's and 1541's workspace, as [(address, size,
  name)].
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
