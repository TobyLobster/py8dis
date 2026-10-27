"""Make py8dis/commodoreromlabels.py (the labels in Commodore's source for the
C64's and VIC-20's Kernal and BASIC ROMs) from the listings made by assembling
that source.

The source is in https://github.com/mist64/cbmsrc, whose build.sh assembles
it with Commodore's own assembler (using https://github.com/mist64/kernalemu),
making build/<directory>.lst for each. Then:

    python3 tools/make_commodore_rom_labels.py cbmsrc/build py8dis/commodoreromlabels.py

It reads build/KERNAL_C64_03.lst, BASIC_C64.lst, KERNAL_VIC_04.lst and
BASIC_VIC.lst. (These assemble to the real ROMs: the C64's Kernal 901227-03
and BASIC 901226-01 to within one byte each; the VIC-20's BASIC 901486-01
exactly; and the VIC-20's Kernal to 901486-06 (NTSC) and 901486-07 (PAL),
apart from small patches and the PAL timing values, with the code at the same
addresses. Its patch area at &e4cf-&e4ff holds different code in those ROMs,
so labels there are left out.)

A label is taken from each line of the listing that has one: an instruction
or data line with a label (the address is the assembler's), or a label alone
on a line. Where an address has more than one, an instruction's or data's
label is preferred to one alone on a line (e.g. RESTOR rather than TBLA0E, the
end of the table before it), then the first. Only labels in each ROM's range
are taken (not the workspace, or constants defined with '=').
"""

import collections
import os
import re
import sys

MNEMONICS = set("ADC AND ASL BCC BCS BEQ BIT BMI BNE BPL BRK BVC BVS CLC CLD CLI CLV CMP CPX CPY DEC DEX DEY EOR INC INX INY "
                "JMP JSR LDA LDX LDY LSR NOP ORA PHA PHP PLA PLP ROL ROR RTI RTS SBC SEC SED SEI STA STX STY TAX TAY TSX TXA TXS TYA".split())

# (variable in the module, listing, what it is, ranges of addresses to take
# labels from, ranges to leave out)
LISTINGS = [
    ("c64_kernal_rom_labels",   "KERNAL_C64_03.lst", "the C64's Kernal ROM (901227-03)",            [(0xe000, 0x10000)], []),
    ("c64_basic_rom_labels",    "BASIC_C64.lst",     "the C64's BASIC ROM (901226-01, &a000-&bfff and &e000-&e4d2)", [(0xa000, 0xc000), (0xe000, 0xe4d3)], []),
    ("vic20_kernal_rom_labels", "KERNAL_VIC_04.lst", "the VIC-20's Kernal ROM (901486-06 and -07)", [(0xe000, 0x10000)], [(0xe4cf, 0xe500)]),
    ("vic20_basic_rom_labels",  "BASIC_VIC.lst",     "the VIC-20's BASIC ROM (901486-01, &c000-&dfff and &e000-&e47b)", [(0xc000, 0xe47c)], []),
]

def listing_labels(path, ranges, excluded):
    """{address: name} for the labels in the listing"""
    text = open(path, errors="replace").read().replace("\r\n", "\n").replace("\r", "\n")
    candidates = collections.defaultdict(list)
    for line in text.split("\n"):
        # e.g. '00344  E50A  B0 07       PLOT   BCS PLOT10'
        m = re.match(r"^\d{5}  ([0-9A-F]{4})  .{12}(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        tokens = m.group(2).split(";")[0].split()
        if not tokens or not re.fullmatch(r"[A-Z][A-Z0-9]*", tokens[0]) or tokens[0] in MNEMONICS:
            continue
        if len(tokens) > 1 and (tokens[1].startswith("=") or tokens[1].startswith("*=")):
            continue
        if not any(lo <= addr < hi for lo, hi in ranges) or any(lo <= addr < hi for lo, hi in excluded):
            continue
        alone = len(tokens) == 1
        candidates[addr].append((1 if alone else 0, tokens[0]))
    labels = {}
    for addr, names in candidates.items():
        names.sort(key=lambda n: n[0])     # (stable, so the first of each kind)
        labels[addr] = names[0][1].lower()
    duplicates = [n for n, c in collections.Counter(labels.values()).items() if c > 1]
    assert not duplicates, duplicates
    return labels

def main():
    build_dir, out = sys.argv[1], sys.argv[2]
    with open(out, "w") as f:
        f.write('''"""
The labels in Commodore's source for the C64's and VIC-20's Kernal and BASIC
ROMs, for commodore.c64() and vic20() to give as optional labels (see their
rom_labels): one name for each address.

Made by tools/make_commodore_rom_labels.py from the listings made by
assembling Commodore's source (https://github.com/mist64/cbmsrc), which
assemble to the real ROMs (see the script).
"""
''')
        for variable, listing, description, ranges, excluded in LISTINGS:
            labels = listing_labels(os.path.join(build_dir, listing), ranges, excluded)
            f.write("\n# %s: %d labels\n%s = {\n" % (description[0].upper() + description[1:], len(labels), variable))
            for addr in sorted(labels):
                f.write("    0x%04x: %r,\n" % (addr, labels[addr]))
            f.write("}\n")
            print("%s: %d labels" % (variable, len(labels)))

if __name__ == "__main__":
    main()
