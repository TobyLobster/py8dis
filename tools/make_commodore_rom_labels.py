"""Make py8dis/commodoreromlabels.py (the labels in Commodore's source for the
C64 Kernal ROM) from c64disasm_cbm.txt in Michael Steil's c64ref
(https://github.com/mist64/c64ref):

    python3 tools/make_commodore_rom_labels.py c64ref/src/c64disasm/c64disasm_cbm.txt py8dis/commodoreromlabels.py

It reports the labels it couldn't place, and the other labels at an address
(of which the module has one).

Labels come from three kinds of line:
- an instruction line with a label ('.,E50A B0 07 BCS $E513   PLOT BCS PLOT10');
- a label alone on a line, which labels the next address line;
- a label with a .BYT or .WOR directive on a line without an address (a data
  table written out in the source, which the listing shows only the start
  of), whose address is worked out from the lengths of the directives before
  it. The run of directives must exactly fill the gap to the next address in
  the listing, and match the bytes the listing shows.
An instruction line's label is preferred to others at the same address."""
import re, sys, collections
src, out = sys.argv[1], sys.argv[2]
MN=set("ADC AND ASL BCC BCS BEQ BIT BMI BNE BPL BRK BVC BVS CLC CLD CLI CLV CMP CPX CPY DEC DEX DEY EOR INC INX INY JMP JSR LDA LDX LDY LSR NOP ORA PHA PHP PLA PLP ROL ROR RTI RTS SBC SEC SED SEI STA STX STY TAX TAY TSX TXA TXS TYA".split())
lines = open(src).read().split("\n")

# The ROM's bytes, from the listing's hex columns
rom = {}
for l in lines:
    if l.startswith(".,") or l.startswith(".:"):
        addr = int(l[2:6], 16)
        for i, h in enumerate(l[7:].split()[:8]):
            if not re.fullmatch(r"[0-9A-F]{2}", h):
                break
            rom[addr + i] = int(h, 16)

def byt_bytes(args):
    """The bytes of a .BYT directive's arguments, or None if they can't be
    worked out (e.g. an expression)"""
    result = []
    for part in re.findall(r"'[^']*'|[^,]+", args):
        part = part.strip()
        if part.startswith("'"):
            result += [ord(c) for c in part[1:-1]]
        elif re.fullmatch(r"\$[0-9A-F]+", part):
            result.append(int(part[1:], 16))
        elif re.fullmatch(r"[0-9]+", part):
            result.append(int(part))
        else:
            return None
    return result

def directive_bytes(directive, text):
    """The bytes of a .BYT or .WOR line (None for a .WOR's, which aren't
    checked), or None if they can't be worked out"""
    args = text.split(directive, 1)[1]
    if directive == ".BYT":
        return byt_bytes(args)
    return [None] * (2 * len(args.split(",")))

IDENT = r"[A-Z][A-Z0-9]*"
candidates = collections.defaultdict(list)   # addr -> [(priority, name)]
pending_alone = []     # labels alone on a line
pending_data = []      # (name, bytes before it in the run, its bytes) for '.BYT' lines without addresses
run_bytes = 0
run_ok = True
seen_code = False
data_runs = []         # (address, pending_data, total bytes or None)
for l in lines:
    if l.startswith(".,") or l.startswith(".:"):
        seen_code = True
        addr = int(l[2:6], 16)
        for name in pending_alone:
            candidates[addr].append((1, name))
        if pending_data:
            # (The address line itself can have the run's last directive)
            own = l[32:].split(";")[0].split()
            directive = [d for d in own if d in (".BYT", ".WOR")]
            if directive:
                own_data = directive_bytes(directive[0], l[32:].split(";")[0])
                run_ok = run_ok and own_data is not None
                if own_data is not None:
                    run_bytes += len(own_data)
            data_runs.append((addr, pending_data, run_bytes if run_ok else None))
        pending_alone, pending_data, run_bytes, run_ok = [], [], 0, True
        toks = l[32:].split()
        if toks and re.fullmatch(IDENT, toks[0]) and toks[0] not in MN:
            candidates[addr].append((0, toks[0]))
    elif seen_code and l.startswith(" " * 32):
        text = l[32:].split(";")[0]
        toks = text.split()
        if not toks:
            continue
        if re.fullmatch(IDENT, toks[0]) and toks[0] not in MN:
            if len(toks) == 1:
                pending_alone.append(toks[0])
            elif toks[1] in (".BYT", ".WOR"):
                data = directive_bytes(toks[1], text) if run_ok else None
                pending_data.append((toks[0], run_bytes, data))
                if data is None:
                    run_ok = False
                else:
                    run_bytes += len(data)
            else:
                print("ignored:", l.strip(), file=sys.stderr)
        elif toks[0] in (".BYT", ".WOR"):
            data = directive_bytes(toks[0], text)
            if data is None:
                run_ok = False
            else:
                run_bytes += len(data)

# Place the data labels: each run of .BYT lines must fill the gap to the next
# address in the listing exactly, and match the bytes the listing shows
addresses = sorted(set(int(l[2:6], 16) for l in lines if l.startswith(".,") or l.startswith(".:")))
for addr, run, total in data_runs:
    following = [a for a in addresses if a > addr]
    ok = total is not None and following and following[0] - addr == total
    for name, offset, data in run:
        a = addr + offset
        if ok and data is not None and all(b is None or rom.get(a + i, b) == b for i, b in enumerate(data)):
            candidates[a].append((2, name))
        else:
            print("data label not placed:", name, file=sys.stderr)

labels = {}
dropped = []
for addr, cands in candidates.items():
    cands.sort(key=lambda c: c[0])
    labels[addr] = cands[0][1]
    dropped += ["%s(%04x)" % (n, addr) for p, n in cands[1:]]
names = collections.Counter(labels.values())
assert all(c == 1 for c in names.values()), [n for n, c in names.items() if c > 1]
with open(out, "w") as f:
    f.write('''"""
The labels in Commodore's source for the C64 Kernal ROM (901227-03), for
commodore.c64() to give as optional labels (see c64(rom_labels=...)): one name
for each address, preferring the label of an instruction where the source
has more than one.

Made by tools/make_commodore_rom_labels.py from src/c64disasm/c64disasm_cbm.txt
in Michael Steil's c64ref (https://github.com/mist64/c64ref), which lines
Commodore's source up with the ROM. (commodoretables.py's names are also from
c64ref.) c64ref's licence:

    BSD 2-Clause License

    Copyright (c) 2022, Michael Steil
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

kernal_rom_labels = {
''')
    for addr in sorted(labels):
        f.write("    0x%04x: %r,\n" % (addr, labels[addr].lower()))
    f.write("}\n")
print(len(labels), "labels; others at the same address:", " ".join(dropped), file=sys.stderr)
