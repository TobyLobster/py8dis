#!/usr/bin/env python3
"""
CPU state tests

Tests for what py8dis knows about the 6502's registers and flags (the sets
of values in py8dis/valuesets.py and the CPU state in py8dis/cpu6502.py),
run by run_tests.py -c when all the tests are run.

1. The functions in valuesets.py: for random sets (nothing known, one
   value, a range, values with some bits known, a few values, or any
   values), each operand and each carry (and an unknown one), the result of
   each function must be exactly what working it out value by value gives:
   the set of results, and each flag known if and only if every value
   agrees on it.

2. The CPU state: for each instruction whose update works on what's known
   about the registers (AND, ORA, EOR, ADC, SBC, CMP, CPX and CPY with an
   immediate operand; ASL, LSR, ROL and ROR of A and of memory; INX, DEX,
   INY, DEY; the transfers and immediate loads; the 65C02's INC A, DEC A
   and BIT #imm; the 6510's ANC and ALR), from a random state (a random set
   for each register, and some flags known), what py8dis says afterwards
   must be what a simple 6502 (below) gives, for every state that agrees
   with what was known before (a random 64 of them): each register must be
   one of the values it says, and each flag it says it knows must be right.
   Where there are few enough states to try them all, what it says must be
   exact too: each register's set is just the values the instruction gives,
   and a flag is known if and only if they all agree on it. The same is
   done (without the exactness) for each of those instructions followed by
   a conditional branch that isn't taken, where the branch says something
   about the result (e.g. A is 1 after 'and #1 : beq skip'), sometimes with
   another instruction between them (e.g. 'cmp #5 : lda #9 : bcs', where
   what CMP said about A no longer holds). And some programs check what's
   known where py8dis's comments rely on it (e.g. X is 0 to 16 at the start
   of a 'dex : bpl' loop that starts with 'ldx #16', and $ff after it).

   Then zero page (see Cpu6502.update_zero_page()): each instruction that
   uses memory in each addressing mode that can reach zero page (loads,
   stores, INC, DEC, the shifts, arithmetic, compares, BIT, the 65C02's
   STZ, TSB and TRB, the 6510's SAX, LAX and DCP; zero page, indexed,
   absolute, and through a pointer), from a random state with some bytes of
   zero page known (the one it uses, or for an index some of those it could
   use, or the pointer, which points into zero page half the time, and a few
   others), sometimes followed by a branch: what py8dis says about the
   registers, the flags and zero page afterwards must be so, for random
   states and memory that agree with what was known; and exact, where there
   are few enough states to try and the instruction uses one byte of zero
   page whose values it works out exactly (see test_zero_page()).

3. Joining at labels (see Cpu6502.join_states_at_labels()): random
   programs of the instructions above, with loads, stores, conditional
   branches (forwards and backwards, so with loops) and jumps, are traced by
   py8dis, then run on the simple 6502 from random states (with D clear) and
   random memory. The instructions include those of zero page (loads,
   stores, INC, DEC, the shifts, arithmetic, compares, BIT, 'zp,X', and
   '(zp),Y' through a pointer that the program sometimes points at zero
   page). At each instruction run, what py8dis says it knows for certain
   after it (about the registers, the flags and zero page) must be so
   (after a branch, only when it isn't taken, and a branch it says is
   always taken must be).

4. What subroutines leave behind (see Cpu6502.subroutine_summaries()):
   random programs with subroutines, which call each other, jump to each
   other (tail calls), push and pull A and the flags (sometimes unevenly,
   so that an RTS goes somewhere else), save registers and flags on the
   stack and get them back (perhaps through A), and write to the stack
   (TSX : STA $01xx,X, which can change what was saved), are traced and run
   on the simple 6502 with a real stack (in its memory, so a write through a
   pointer can change it). What py8dis says it knows is checked as in 3,
   and what it says it knows after a JSR is checked when the call returns
   (including the bytes of zero page that the subroutine, a subroutine it
   calls, or one it jumps to, writes or doesn't write). A run stops at an RTS that doesn't return to a call
   (it's a jump to an address that was pushed, which py8dis can't follow).

The tests are randomised with a fixed seed, so they're the same each run.

Usage: ./cpu_state_tests.py   (exits with 1 if any fail)
"""

import collections
import functools
import random
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"
sys.path.insert(0, str(PY8DIS_DIR))

import valuesets

failures = []

def fail(message):
    failures.append(message)
    if len(failures) <= 20:
        print("FAIL: " + message)


# 1. valuesets.py

def random_set(rng):
    """A random set of values: nothing known, one value, a range, the values
    that agree with some known bits, a few values, or any values."""
    choice = rng.random()
    if choice < 0.1:
        return valuesets.FULL
    if choice < 0.3:
        return valuesets.exact(rng.randrange(256))
    if choice < 0.5:
        lo = rng.randrange(256)
        return valuesets.from_range(lo, rng.randrange(lo, 256))
    if choice < 0.7:
        known = rng.randrange(256)
        return valuesets.from_known_bits(known, rng.randrange(256) & known)
    if choice < 0.9:
        s = 0
        for _ in range(rng.randint(1, 5)):
            s |= valuesets.exact(rng.randrange(256))
        return s
    return rng.getrandbits(256) or 1

def random_carry(rng):
    return rng.choice([None, True, False])

def carries(c):
    return [0, 1] if c is None else [int(c)]

def image(s, carry, f):
    """The set of f(v, c) & $ff for each value v in s and carry c."""
    result = 0
    for v in valuesets.values(s):
        for c in carries(carry):
            result |= 1 << (f(v, c) & 0xff)
    return result

def agree(flags):
    """The flag, if all of them are the same, otherwise None."""
    flags = set(bool(f) for f in flags)
    return flags.pop() if len(flags) == 1 else None

def check_exact(name, got, want, inputs):
    if got != want:
        fail("%s: gave %s, but it's %s, for %s" % (name, valuesets.describe(got), valuesets.describe(want), inputs))

def check_flag_exact(name, got, want, inputs):
    if got != want:
        fail("%s: gave %s, but it's %s, for %s" % (name, got, want, inputs))

def check_flag(name, claimed, actual, inputs):
    if claimed is not None and bool(claimed) != bool(actual):
        fail("%s: says %s, but it's %s, for %s" % (name, claimed, actual, inputs))

def test_valuesets(rng):
    for _ in range(3000):
        s = random_set(rng)
        n = rng.randrange(256)
        carry = random_carry(rng)
        vs = valuesets.values(s)
        inputs = "%s, #$%02x, carry %s" % (valuesets.describe(s), n, carry)
        cs = carries(carry)
        if not vs:
            fail("random_set gave an empty set")
            continue
        if valuesets.bounds(s) != (min(vs), max(vs)):
            fail("bounds: wrong for " + inputs)
        known = ~functools.reduce(lambda a, b: a | (b ^ vs[0]), vs, 0) & 0xff
        if valuesets.known_bits(s) != (known, vs[0] & known):
            fail("known_bits: wrong for " + inputs)
        if valuesets.from_known_bits(*valuesets.known_bits(s)) & s != s:
            fail("from_known_bits: doesn't include the set for " + inputs)
        if valuesets.value(s) != (vs[0] if len(vs) == 1 else None) or valuesets.count(s) != len(vs):
            fail("value or count: wrong for " + inputs)
        check_flag_exact("n_flag", valuesets.n_flag(s), agree(v >= 0x80 for v in vs), inputs)
        check_flag_exact("z_flag", valuesets.z_flag(s), agree(v == 0 for v in vs), inputs)
        for k in range(8):
            check_flag_exact("bit %d" % k, valuesets.bit(s, k), agree((v >> k) & 1 for v in vs), inputs)
        check_exact("and_", valuesets.and_(s, n), image(s, 0, lambda v, c: v & n), inputs)
        check_exact("or_", valuesets.or_(s, n), image(s, 0, lambda v, c: v | n), inputs)
        check_exact("eor", valuesets.eor(s, n), image(s, 0, lambda v, c: v ^ n), inputs)
        check_exact("rotate", valuesets.rotate(s, n), image(s, 0, lambda v, c: v + n), inputs)
        for name, (result, carry_out), want, want_carry in (
                ("asl", valuesets.asl(s), image(s, 0, lambda v, c: v << 1), agree(v >> 7 for v in vs)),
                ("lsr", valuesets.lsr(s), image(s, 0, lambda v, c: v >> 1), agree(v & 1 for v in vs)),
                ("rol", valuesets.rol(s, carry), image(s, carry, lambda v, c: (v << 1) | c), agree(v >> 7 for v in vs)),
                ("ror", valuesets.ror(s, carry), image(s, carry, lambda v, c: (v >> 1) | (c << 7)), agree(v & 1 for v in vs)),
                ("add", valuesets.add(s, n, carry), image(s, carry, lambda v, c: v + n + c), agree(v + n + c > 0xff for v in vs for c in cs)),
                ("subtract", valuesets.subtract(s, n, carry), image(s, carry, lambda v, c: v - n - (1 - c)), agree(v - n - (1 - c) >= 0 for v in vs for c in cs))):
            check_exact(name, result, want, inputs)
            check_flag_exact(name + " carry", carry_out, want_carry, inputs)
        for subtracting in (False, True):
            m = (~n & 0xff) if subtracting else n
            want = agree((v ^ ((v + m + c) & 0xff)) & (m ^ ((v + m + c) & 0xff)) & 0x80 for v in vs for c in cs)
            check_flag_exact("overflow" + (" (subtracting)" if subtracting else ""), valuesets.overflow(s, n, carry, subtracting), want, inputs)
        flags = valuesets.compare(s, n)
        want = (agree(((v - n) & 0xff) >= 0x80 for v in vs), agree(v == n for v in vs), agree(v >= n for v in vs))
        check_flag_exact("compare (N, Z, C)", flags, want, inputs)


# 2. The CPU state

def step(opcode, operand, s):
    """A simple 6502: run the instruction (opcode, operand) on s (a dict
    of a, x, y, m (the memory operand), n, v, d, i, z, c, with the flags as
    bools), changing s. Returns False if its result isn't modelled (ADC or
    SBC in decimal mode), else True."""
    def nz(v):
        s['n'] = bool(v & 0x80)
        s['z'] = v == 0
        return v
    def adc(value):
        if s['d']:
            return False
        a = s['a']
        total = a + value + s['c']
        r = total & 0xff
        s['v'] = bool((a ^ r) & (value ^ r) & 0x80)
        s['c'] = total > 0xff
        s['a'] = nz(r)
        return True
    def compare(reg):
        total = s[reg] + (~operand & 0xff) + 1
        s['c'] = total > 0xff
        nz(total & 0xff)
    if opcode == 0x29:   s['a'] = nz(s['a'] & operand)
    elif opcode == 0x09: s['a'] = nz(s['a'] | operand)
    elif opcode == 0x49: s['a'] = nz(s['a'] ^ operand)
    elif opcode == 0x69: return adc(operand)
    elif opcode == 0xe9: return adc(~operand & 0xff)
    elif opcode == 0xc9: compare('a')
    elif opcode == 0xe0: compare('x')
    elif opcode == 0xc0: compare('y')
    elif opcode in (0x0a, 0x06, 0x2a, 0x26, 0x4a, 0x46, 0x6a, 0x66):
        reg = 'a' if opcode & 0xf == 0xa else 'm'
        v = s[reg]
        kind = opcode >> 5
        if kind == 0:   r, c = (v << 1) & 0xff, v >> 7
        elif kind == 1: r, c = ((v << 1) | s['c']) & 0xff, v >> 7
        elif kind == 2: r, c = v >> 1, v & 1
        else:           r, c = (v >> 1) | (0x80 if s['c'] else 0), v & 1
        s[reg] = nz(r)
        s['c'] = bool(c)
    elif opcode == 0xe8: s['x'] = nz((s['x'] + 1) & 0xff)
    elif opcode == 0xca: s['x'] = nz((s['x'] - 1) & 0xff)
    elif opcode == 0xc8: s['y'] = nz((s['y'] + 1) & 0xff)
    elif opcode == 0x88: s['y'] = nz((s['y'] - 1) & 0xff)
    elif opcode == 0x1a: s['a'] = nz((s['a'] + 1) & 0xff)      # 65C02
    elif opcode == 0x3a: s['a'] = nz((s['a'] - 1) & 0xff)      # 65C02
    elif opcode == 0x89: s['z'] = (s['a'] & operand) == 0      # 65C02
    elif opcode == 0xaa: s['x'] = nz(s['a'])
    elif opcode == 0x8a: s['a'] = nz(s['x'])
    elif opcode == 0xa8: s['y'] = nz(s['a'])
    elif opcode == 0x98: s['a'] = nz(s['y'])
    elif opcode == 0xa9: s['a'] = nz(operand)
    elif opcode == 0xa2: s['x'] = nz(operand)
    elif opcode == 0xa0: s['y'] = nz(operand)
    elif opcode == 0x18: s['c'] = False                        # CLC
    elif opcode == 0x38: s['c'] = True                         # SEC
    elif opcode == 0x0b:                                        # 6510: ANC
        s['a'] = nz(s['a'] & operand)
        s['c'] = s['n']
    elif opcode == 0x4b:                                        # 6510: ALR
        v = s['a'] & operand
        s['c'] = bool(v & 1)
        s['a'] = nz(v >> 1)
    else:
        assert False, hex(opcode)
    return True

# The instructions tested, with the CPU they're for
INSTRUCTIONS = [(op, "6502") for op in (0x29, 0x09, 0x49, 0x69, 0xe9, 0xc9, 0xe0, 0xc0, 0x0a, 0x06, 0x2a, 0x26,
                                        0x4a, 0x46, 0x6a, 0x66, 0xe8, 0xca, 0xc8, 0x88, 0xaa, 0x8a, 0xa8, 0x98,
                                        0xa9, 0xa2, 0xa0, 0x18, 0x38)] + \
               [(op, "65C02") for op in (0x1a, 0x3a, 0x89)] + [(op, "6510") for op in (0x0b, 0x4b)]

# The branches: (opcode, flag, the value the flag has if it isn't taken)
BRANCHES = [(0x10, 'n', True), (0x30, 'n', False), (0x50, 'v', True), (0x70, 'v', False),
            (0x90, 'c', True), (0xb0, 'c', False), (0xd0, 'z', True), (0xf0, 'z', False)]

# The z_from inferences (from BNE) assume binary arithmetic, as py8dis
# always has: so ADC and SBC are followed by a branch only with D clear
DECIMAL_SENSITIVE = (0x69, 0xe9)

# The instructions that use memory, for the zero page tests: by opcode,
# (operation, addressing mode, the CPU they're for). The modes are zp,
# zpx and zpy ('zp,X' and 'zp,Y'), abs and absx ('addr' and 'addr,X', used
# with addresses in zero page or that wrap round to it), izy, izx and iz
# ('(zp),Y', '(zp,X)' and the 65C02's '(zp)')
MEMORY_OPCODES = {
    0xa5: ("lda", "zp", "6502"), 0xa6: ("ldx", "zp", "6502"), 0xa4: ("ldy", "zp", "6502"),
    0xb5: ("lda", "zpx", "6502"), 0xb4: ("ldy", "zpx", "6502"), 0xb6: ("ldx", "zpy", "6502"),
    0x85: ("sta", "zp", "6502"), 0x86: ("stx", "zp", "6502"), 0x84: ("sty", "zp", "6502"),
    0x95: ("sta", "zpx", "6502"), 0x94: ("sty", "zpx", "6502"), 0x96: ("stx", "zpy", "6502"),
    0xe6: ("inc", "zp", "6502"), 0xc6: ("dec", "zp", "6502"), 0xf6: ("inc", "zpx", "6502"), 0xd6: ("dec", "zpx", "6502"),
    0x06: ("asl", "zp", "6502"), 0x26: ("rol", "zp", "6502"), 0x46: ("lsr", "zp", "6502"), 0x66: ("ror", "zp", "6502"),
    0x16: ("asl", "zpx", "6502"), 0x76: ("ror", "zpx", "6502"),
    0x25: ("and", "zp", "6502"), 0x05: ("ora", "zp", "6502"), 0x45: ("eor", "zp", "6502"),
    0x65: ("adc", "zp", "6502"), 0xe5: ("sbc", "zp", "6502"),
    0xc5: ("cmp", "zp", "6502"), 0xe4: ("cpx", "zp", "6502"), 0xc4: ("cpy", "zp", "6502"), 0x24: ("bit", "zp", "6502"),
    0x35: ("and", "zpx", "6502"), 0xd5: ("cmp", "zpx", "6502"),
    0xb1: ("lda", "izy", "6502"), 0x91: ("sta", "izy", "6502"), 0x11: ("ora", "izy", "6502"),
    0xa1: ("lda", "izx", "6502"), 0x81: ("sta", "izx", "6502"),
    0xad: ("lda", "abs", "6502"), 0x8d: ("sta", "abs", "6502"), 0xee: ("inc", "abs", "6502"), 0x2d: ("and", "abs", "6502"),
    0xbd: ("lda", "absx", "6502"), 0x9d: ("sta", "absx", "6502"),
    0x64: ("stz", "zp", "65C02"), 0x74: ("stz", "zpx", "65C02"), 0x9c: ("stz", "abs", "65C02"),
    0xb2: ("lda", "iz", "65C02"), 0x92: ("sta", "iz", "65C02"),
    0x04: ("tsb", "zp", "65C02"), 0x14: ("trb", "zp", "65C02"), 0x34: ("bit", "zpx", "65C02"),
    0x87: ("sax", "zp", "6510"), 0xa7: ("lax", "zp", "6510"), 0xb7: ("lax", "zpy", "6510"), 0xc7: ("dcp", "zp", "6510"),
}

# The opcodes with an immediate operand that do what each operation does
# with its operand, and those for the shifts of memory (see step())
IMMEDIATE_OPCODES = {"and": 0x29, "ora": 0x09, "eor": 0x49, "adc": 0x69, "sbc": 0xe9, "cmp": 0xc9, "cpx": 0xe0, "cpy": 0xc0}
SHIFT_OPCODES = {"asl": 0x06, "rol": 0x26, "lsr": 0x46, "ror": 0x66}

class Memory:
    """The simple 6502's memory: zero page (a list of 256 bytes), and the
    rest, random until it's written (the same each time it's read)."""

    def __init__(self, rng, zero_page):
        self.zero_page = zero_page
        self.rest = {}
        self.rng = rng

    def __getitem__(self, address):
        if address < 0x100:
            return self.zero_page[address]
        if address not in self.rest:
            self.rest[address] = self.rng.randrange(256)
        return self.rest[address]

    def __setitem__(self, address, value):
        if address < 0x100:
            self.zero_page[address] = value
        else:
            self.rest[address] = value

def instruction_length(opcode):
    """The length of an instruction in MEMORY_OPCODES."""
    return 3 if MEMORY_OPCODES[opcode][1] in ("abs", "absx") else 2

def effective_address(mode, operand_bytes, s, memory):
    """The address that an instruction with the addressing mode and operand
    uses, in the state s with memory."""
    if mode == "zp":
        return operand_bytes[0]
    if mode == "zpx":
        return (operand_bytes[0] + s['x']) & 0xff
    if mode == "zpy":
        return (operand_bytes[0] + s['y']) & 0xff
    if mode == "abs":
        return operand_bytes[0] | operand_bytes[1] << 8
    if mode == "absx":
        return ((operand_bytes[0] | operand_bytes[1] << 8) + s['x']) & 0xffff
    p = operand_bytes[0]
    if mode == "izx":
        p = (p + s['x']) & 0xff
    pointer = memory[p] | memory[(p + 1) & 0xff] << 8
    return (pointer + s['y']) & 0xffff if mode == "izy" else pointer

def execute(opcode, operand_bytes, s, memory):
    """The simple 6502 (see step()) for an instruction in MEMORY_OPCODES:
    run it on s and memory (a Memory, or a list for zero page alone),
    changing them. Returns False if its result isn't modelled (ADC or SBC
    in decimal mode), else True."""
    operation, mode, _ = MEMORY_OPCODES[opcode]
    address = effective_address(mode, operand_bytes, s, memory)
    def nz(v):
        s['n'] = bool(v & 0x80)
        s['z'] = v == 0
        return v
    if operation in ("lda", "ldx", "ldy"):
        s[operation[2]] = nz(memory[address])
    elif operation == "lax":
        s['a'] = s['x'] = nz(memory[address])
    elif operation in ("sta", "stx", "sty"):
        memory[address] = s[operation[2]]
    elif operation == "stz":
        memory[address] = 0
    elif operation == "sax":
        memory[address] = s['a'] & s['x']
    elif operation in ("inc", "dec"):
        memory[address] = nz((memory[address] + (1 if operation == "inc" else -1)) & 0xff)
    elif operation in SHIFT_OPCODES:
        s['m'] = memory[address]
        step(SHIFT_OPCODES[operation], 0, s)
        memory[address] = s['m']
    elif operation in IMMEDIATE_OPCODES:
        return step(IMMEDIATE_OPCODES[operation], memory[address], s)
    elif operation == "bit":
        m = memory[address]
        s['z'] = (s['a'] & m) == 0
        s['n'] = bool(m & 0x80)
        s['v'] = bool(m & 0x40)
    elif operation in ("tsb", "trb"):
        m = memory[address]
        s['z'] = (s['a'] & m) == 0
        memory[address] = (m | s['a']) if operation == "tsb" else (m & ~s['a'] & 0xff)
    elif operation == "dcp":
        memory[address] = (memory[address] - 1) & 0xff
        step(0xc9, memory[address], s)
    else:
        assert False, operation
    return True

def check_zero_page(name, disposition, memory, inputs):
    """What the disposition says it knows about zero page must be what's
    in memory."""
    for address, possible in disposition.zp.items():
        if not (possible >> memory[address]) & 1:
            fail("%s $%02x: says %s, but it's %d, for %s" % (name, address, valuesets.describe(possible), memory[address], inputs))

def random_flag(rng):
    return rng.choice([None, None, True, False])

def make_cpu(name):
    import cpu6502
    import cpu65C02
    import cpu6510
    return {"6502": cpu6502.Cpu6502, "65C02": cpu65C02.Cpu65C02, "6510": cpu6510.Cpu6510}[name]()

def set_disposition(disposition, regs, flags):
    for reg in "axy":
        disposition[reg].possible = regs[reg]
    for flag in "nvdizc":
        disposition[flag] = flags[flag]

def check_disposition(name, disposition, s, inputs):
    """What the disposition says it knows must be what s (the 6502's
    state) is."""
    for reg in "axy":
        r = disposition[reg]
        if not (r.possible >> s[reg]) & 1:
            fail("%s %s: says %s, but it's %d, for %s" % (name, reg.upper(), valuesets.describe(r.possible), s[reg], inputs))
    for flag in "nvdizc":
        value = disposition[flag]
        if value == 'pending':
            continue
        check_flag(name + " flag " + flag, value, s[flag], inputs)

def check_disposition_exact(name, disposition, states, inputs):
    """What the disposition says must be exactly what the 6502's states
    (all those that agree with what was known before, after the
    instruction) are: each register's set of values, and each flag, known
    if they all agree on it."""
    for reg in "axy":
        want = functools.reduce(lambda a, b: a | b, (1 << s[reg] for s in states))
        check_exact(name + " " + reg.upper(), disposition[reg].possible, want, inputs)
    for flag in "nvdizc":
        value = disposition[flag]
        claimed = None if value is None or value == 'pending' else bool(value)
        check_flag_exact(name + " flag " + flag, claimed, agree(s[flag] for s in states), inputs)

def show_inputs(regs, flags):
    return "A:%s X:%s Y:%s %s" % (valuesets.describe(regs['a']), valuesets.describe(regs['x']), valuesets.describe(regs['y']),
                                 "".join("-" if flags[f] is None else (f.upper() if flags[f] else f) for f in "nvdizc"))

def concrete_states(regs, flags, rng, count=64):
    """Random 6502 states that agree with what's known (the registers' sets
    of values, and the flags)."""
    choices = {reg: valuesets.values(regs[reg]) for reg in "axy"}
    result = []
    for _ in range(count):
        s = {}
        for reg in "axy":
            s[reg] = rng.choice(choices[reg])
        s['m'] = rng.randrange(256)
        for flag in "nvdizc":
            s[flag] = rng.choice([False, True]) if flags[flag] is None else flags[flag]
        result.append(s)
    return result

def all_states(regs, flags, limit=2048):
    """All the 6502 states that agree with what's known (with memory 0), or
    None if there are more than 'limit'."""
    states = [{'m': 0}]
    for reg in "axy":
        vs = valuesets.values(regs[reg])
        if len(states) * len(vs) > limit:
            return None
        states = [dict(s, **{reg: v}) for s in states for v in vs]
    for flag in "nvdizc":
        options = [False, True] if flags[flag] is None else [flags[flag]]
        if len(states) * len(options) > limit:
            return None
        states = [dict(s, **{flag: o}) for s in states for o in options]
    return states

# The instructions that work on memory (whose value py8dis doesn't know),
# so what it says about them can't be exact
MEMORY_INSTRUCTIONS = (0x06, 0x26, 0x46, 0x66)

def test_cpu_state(rng):
    import memorymanager
    import session
    count = 0
    sessions = {}
    for opcode, cpu_name in INSTRUCTIONS:
        if cpu_name not in sessions:
            # (One session for each CPU, since making one takes a while;
            # nothing in it is labelled, so each update starts afresh)
            s = session.new_session(assembler="acme")
            s.cpu = make_cpu(cpu_name)
            sessions[cpu_name] = s
        s = sessions[cpu_name]
        session.set_current(s)
        cpu = s.cpu
        for trial in range(400):
            with_branch = trial % 2 == 1
            # (Every fourth trial has few enough states to try them all, so
            # what py8dis says can be checked for exactness)
            few = trial % 4 == 0
            branch = rng.choice(BRANCHES) if with_branch else None
            operand = rng.randrange(256)
            # Sometimes another instruction between this one and the branch
            # (e.g. 'cmp #5 : lda #9 : bcs': what CMP says about A no longer
            # holds after LDA)
            middle = None
            if with_branch and rng.random() < 0.4:
                middle = (rng.choice([op for op, name in INSTRUCTIONS if name == "6502" and op not in DECIMAL_SENSITIVE]), rng.randrange(256))
            # (The branch goes to $2010, so it isn't to the next instruction)
            s.memory.binary[0x2000:0x2006] = [opcode, operand] + (list(middle) if middle else [0xea, 0xea]) + ([branch[0], 0x0a] if with_branch else [0xea, 0xea])
            regs = {reg: random_set(rng) for reg in "axy"}
            flags = {flag: random_flag(rng) for flag in "nvdizc"}
            if few:
                # (One register with a random set, and the others one value
                # each; most flags known)
                varied = rng.choice("axy")
                for reg in "axy":
                    if reg != varied:
                        regs[reg] = valuesets.exact(rng.randrange(256))
                for flag in "nvdizc":
                    if rng.random() < 0.7:
                        flags[flag] = rng.choice([False, True])
            if with_branch and opcode in DECIMAL_SENSITIVE:
                flags['d'] = False
            state = cpu.CpuState()
            set_disposition(state.pessimistic, regs, flags)
            set_disposition(state.optimistic, regs, flags)
            cpu.opcodes[opcode].update_cpu_state(memorymanager.BinaryAddr(0x2000), state)
            after_instruction = state.copy()
            if middle:
                cpu.opcodes[middle[0]].update_cpu_state(memorymanager.BinaryAddr(0x2002), state)
            if with_branch:
                cpu.opcodes[branch[0]].update_cpu_state(memorymanager.BinaryAddr(0x2004), state)
            inputs = "opcode %02x #%02x%s%s from %s" % (
                opcode, operand, (" then %02x #%02x" % middle) if middle else "", (" then branch %02x" % branch[0]) if with_branch else "",
                show_inputs(regs, flags))
            if few and opcode not in MEMORY_INSTRUCTIONS:
                states = all_states(regs, flags)
                if states is not None and all(step(opcode, operand, st) for st in states):
                    check_disposition_exact("exact", after_instruction.pessimistic, states, inputs)
                    count += 1
            for concrete in concrete_states(regs, flags, rng):
                if not step(opcode, operand, concrete):
                    # (Decimal ADC or SBC: py8dis mustn't claim anything about the result)
                    d = after_instruction.pessimistic
                    if d['a'].possible != valuesets.FULL or any(d[f] not in (None, 'pending') for f in "nvzc"):
                        fail("decimal: claims something for " + inputs)
                    continue
                count += 1
                check_disposition("after", after_instruction.pessimistic, concrete, inputs)
                check_disposition("after (optimistic)", after_instruction.optimistic, concrete, inputs)
                if middle:
                    step(middle[0], middle[1], concrete)
                if with_branch and not state.always_branch and concrete[branch[1]] == branch[2]:
                    # The branch isn't taken in this state
                    check_disposition("after the branch", state.pessimistic, concrete, inputs)
                if with_branch and state.always_branch and concrete[branch[1]] == branch[2]:
                    fail("ALWAYS branch, but it isn't taken, for " + inputs)
    return count


def show_zero_page(zp):
    return " ".join("$%02x:%s" % (address, valuesets.describe(possible)) for address, possible in sorted(zp.items())) or "nothing"

def test_zero_page(rng, trials=300):
    """Each instruction in MEMORY_OPCODES (sometimes followed by a branch
    that isn't taken), from a random state with some bytes of zero page
    known (the one it uses, or for a pointer the pointer, and others): what
    py8dis says about the registers, the flags and zero page afterwards must
    be so, for random states and memory that agree with what was known.
    Where it uses one byte of zero page (its index, or pointer, being known)
    that it doesn't read unless that's known, and there are few enough
    states to try them all, what it says must be exact too: loads, stores,
    INC, DEC and the shifts with any set of values, and AND, ORA, EOR, ADC,
    SBC, CMP, CPX, CPY and BIT with one value."""
    import memorymanager
    import session
    count = 0
    sessions = {}
    exact_operations = {"lda", "ldx", "ldy", "sta", "stx", "sty", "stz", "inc", "dec", "asl", "rol", "lsr", "ror"}
    one_value_operations = set(IMMEDIATE_OPCODES) | {"bit"}
    for opcode, (operation, mode, cpu_name) in sorted(MEMORY_OPCODES.items()):
        if cpu_name not in sessions:
            s = session.new_session(assembler="acme")
            s.cpu = make_cpu(cpu_name)
            s.cpu._untracked_zero_page = frozenset()
            sessions[cpu_name] = s
        s = sessions[cpu_name]
        session.set_current(s)
        cpu = s.cpu
        length = instruction_length(opcode)
        for trial in range(trials):
            few = trial % 3 == 0
            with_branch = trial % 2 == 1
            branch = rng.choice(BRANCHES) if with_branch else None
            if mode == "abs":
                operand_bytes = [rng.randrange(256), 0]
            elif mode == "absx":
                operand_bytes = [rng.randrange(256), rng.choice([0, 0xff])]
            else:
                operand_bytes = [rng.randrange(256)]
            regs = {reg: random_set(rng) for reg in "axy"}
            flags = {flag: random_flag(rng) for flag in "nvdizc"}
            if operation in ("adc", "sbc", "dcp"):
                # (Decimal arithmetic isn't modelled; a branch after ADC or
                # SBC assumes binary)
                flags['d'] = False
            # What's known about zero page: the byte used (for an index, one
            # of those it could be), or the pointer, and a few others
            zp = {}
            def know(address, possible):
                if possible != valuesets.FULL:
                    zp[address & 0xff] = possible
            if mode in ("zp", "abs") or (mode == "absx" and operand_bytes[1] == 0):
                know(operand_bytes[0], random_set(rng))
            elif mode in ("zpx", "zpy", "absx"):
                index = mode[-1]
                if rng.random() < 0.6:
                    regs[index] = valuesets.exact(rng.randrange(256)) if rng.random() < 0.7 else random_set(rng)
                values = valuesets.values(regs[index])
                for v in rng.sample(values, min(3, len(values))):
                    know(operand_bytes[0] + v, random_set(rng))
            else:
                # (A pointer, pointing into zero page half the time)
                if rng.random() < 0.7:
                    target = rng.randrange(256) | (0 if rng.random() < 0.5 else rng.randrange(256) << 8)
                    p = operand_bytes[0]
                    if mode == "izx":
                        x = rng.randrange(256)
                        regs['x'] = valuesets.exact(x)
                        p = (p + x) & 0xff
                    if mode == "izy" and rng.random() < 0.7:
                        regs['y'] = valuesets.exact(rng.randrange(256))
                    know(p, valuesets.exact(target & 0xff))
                    know(p + 1, valuesets.exact(target >> 8))
                    for v in rng.sample(valuesets.values(regs['y']), min(2, len(valuesets.values(regs['y'])))):
                        if (target + v) & 0xffff < 0x100:
                            know(target + v, random_set(rng))
            for _ in range(rng.randrange(3)):
                know(rng.randrange(256), random_set(rng))
            if few:
                # (One register or one byte of zero page with a random set,
                # and everything else one value; most flags known)
                varied = rng.choice(["a", "x", "y"] + sorted(zp))
                for reg in "axy":
                    if reg != varied:
                        regs[reg] = valuesets.exact(rng.choice(valuesets.values(regs[reg])))
                for address in zp:
                    if address != varied:
                        zp[address] = valuesets.exact(rng.choice(valuesets.values(zp[address])))
                for flag in "nvdizc":
                    if flags[flag] is None and rng.random() < 0.7:
                        flags[flag] = rng.choice([False, True])
            s.memory.binary[0x2000:0x2000 + length + 2] = [opcode] + operand_bytes + ([branch[0], 0x0a] if with_branch else [0xea, 0xea])
            state = cpu.CpuState()
            for d in (state.pessimistic, state.optimistic):
                set_disposition(d, regs, flags)
                d.zp = dict(zp)
            cpu.opcodes[opcode].update_cpu_state(memorymanager.BinaryAddr(0x2000), state)
            after_instruction = state.copy()
            if with_branch:
                cpu.opcodes[branch[0]].update_cpu_state(memorymanager.BinaryAddr(0x2000 + length), state)
            inputs = "opcode %02x %s%s from %s, zero page %s" % (
                opcode, " ".join("%02x" % b for b in operand_bytes), (" then branch %02x" % branch[0]) if with_branch else "",
                show_inputs(regs, flags), show_zero_page(zp))
            if few:
                states = all_zero_page_states(regs, flags, zp, rng)
                if states is not None:
                    addresses = set(effective_address(mode, operand_bytes, st, st['memory']) for st in states)
                    address = next(iter(addresses))
                    reads = operation not in ("sta", "stx", "sty", "stz")
                    # (Through a pointer, py8dis knows where only if it knows
                    # the pointer: the other bytes of zero page are the same
                    # in each state, but not known)
                    if mode in ("izy", "izx", "iz"):
                        x_values = valuesets.values(regs['x'])
                        p = (operand_bytes[0] + (x_values[0] if mode == "izx" else 0)) & 0xff
                        pointer_known = (mode != "izx" or len(x_values) == 1) and p in zp and (p + 1) & 0xff in zp
                    else:
                        pointer_known = True
                    if (len(addresses) == 1 and address < 0x100 and (address in zp or not reads) and pointer_known
                            and (operation in exact_operations or (operation in one_value_operations and valuesets.value(zp[address]) is not None))):
                        if all(execute(opcode, operand_bytes, st, st['memory']) for st in states):
                            check_disposition_exact("exact", after_instruction.pessimistic, states, inputs)
                            for a in set(zp) | {address}:
                                want = functools.reduce(lambda x, y: x | y, (1 << st['memory'][a] for st in states))
                                check_exact("exact $%02x" % a, after_instruction.pessimistic.zp.get(a, valuesets.FULL), want, inputs)
                            count += 1
            # (The values each register and known byte could have)
            reg_values = {reg: valuesets.values(regs[reg]) for reg in "axy"}
            zp_values = {address: valuesets.values(possible) for address, possible in zp.items()}
            for _ in range(48):
                concrete = {reg: rng.choice(reg_values[reg]) for reg in "axy"}
                for flag in "nvdizc":
                    concrete[flag] = rng.choice([False, True]) if flags[flag] is None else flags[flag]
                zero_page = list(rng.randbytes(256))
                for address, values in zp_values.items():
                    zero_page[address] = rng.choice(values)
                memory = Memory(rng, zero_page)
                if not execute(opcode, operand_bytes, concrete, memory):
                    continue
                count += 1
                for name, d in (("after", after_instruction.pessimistic), ("after (optimistic)", after_instruction.optimistic)):
                    check_disposition(name, d, concrete, inputs)
                    check_zero_page(name, d, memory, inputs)
                if with_branch and concrete[branch[1]] == branch[2]:
                    if state.always_branch:
                        fail("ALWAYS branch, but it isn't taken, for " + inputs)
                    else:
                        check_disposition("after the branch", state.pessimistic, concrete, inputs)
                        check_zero_page("after the branch", state.pessimistic, memory, inputs)
    return count

def all_zero_page_states(regs, flags, zp, rng, limit=2048):
    """All the 6502 states that agree with what's known (as all_states()),
    with what's known about zero page (the rest of memory random, the same
    in each state), each with its memory as 'memory', or None if there are
    more than 'limit'."""
    states = all_states(regs, flags, limit)
    if states is None:
        return None
    base = list(rng.randbytes(256))
    states = [dict(st, zero_page=list(base)) for st in states]
    for address, possible in sorted(zp.items()):
        vs = valuesets.values(possible)
        if len(states) * len(vs) > limit:
            return None
        states = [dict(st, zero_page=st['zero_page'][:address] + [v] + st['zero_page'][address + 1:]) for st in states for v in vs]
    for st in states:
        st['memory'] = Memory(rng, st.pop('zero_page'))
    return states


# Programs for test_examples(), each (description, bytes at $2000, and
# (address, register, the set of values it's known to have after the
# instruction there))
EXAMPLES = [
    # ldx #16 : loop: dex : bpl loop : txa : rts. At the loop X is 0 to 16,
    # so after DEX it's $ff or 0 to 15 (the range wraps round), and after
    # the loop (BPL not taken) it's $ff
    ("dex : bpl loop", "a210ca10fd8a60",
     [(0x2002, "x", valuesets.from_range(0, 15) | valuesets.exact(0xff)), (0x2005, "a", valuesets.exact(0xff))]),
    # lda $70 : cmp #$cf : bcc skip : asl : tax : skip: rts. A is $cf to $ff
    # after BCC, so the even values $9e to $fe after ASL (49 of them)
    ("asl after cmp #$cf : bcc", "a570c9cf90020aaa60",
     [(0x2007, "x", valuesets.from_range(0x9e, 0xfe) & ~valuesets.from_known_bits(1, 1))]),
    # lda $70 : bmi neg : lda #0 : beq done : neg: lda #$80 : done: tax :
    # rts. A is 0 or $80 at 'done'
    ("joining 0 and $80", "a5703004a900f002a980aa60",
     [(0x200a, "x", valuesets.exact(0) | valuesets.exact(0x80))]),
    # lda $80 : bmi neg : lda #1 : sta $70 : bne done : neg: lda #2 : sta
    # $70 : done: ldx $70 : rts. $70 is 1 or 2 at 'done'
    ("joining zero page 1 and 2", "a5803006a9018570d004a9028570a67060",
     [(0x200e, "x", valuesets.exact(1) | valuesets.exact(2))]),
]

def traced(program_bytes):
    """The CPU of a session with the program (bytes at $2000) traced from
    $2000."""
    import commands
    import os
    import session
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(bytes(program_bytes))
        filename = f.name
    try:
        session.new_session(assembler="acme")
        commands.load(0x2000, filename, "6502")
        commands.entry(0x2000)
        cpu = session.current().cpu
        cpu.trace()
    finally:
        os.unlink(filename)
    return cpu

def test_examples():
    """What py8dis knows after some instructions that its comments rely on
    (see EXAMPLES), exactly."""
    count = 0
    for description, program, checks in EXAMPLES:
        cpu = traced(bytes.fromhex(program))
        for addr, reg, want in checks:
            state = cpu.cpu_states[addr]
            got = None if state is None else state.pessimistic[reg].possible
            if got != want:
                fail("%s: %s at $%04x is %s, not %s" % (description, reg.upper(), addr, "nothing" if got is None else valuesets.describe(got), valuesets.describe(want)))
            count += 1
    return count


# 3. Joining at labels

# The instructions of the random programs: (opcode, length), by kind
PROGRAM_IMMEDIATE = [0xa9, 0xa2, 0xa0, 0x29, 0x09, 0x49, 0x69, 0xe9, 0xc9, 0xe0, 0xc0]
PROGRAM_IMPLIED = [0x0a, 0x2a, 0x4a, 0x6a, 0xe8, 0xca, 0xc8, 0x88, 0xaa, 0x8a, 0xa8, 0x98, 0x18, 0x38, 0xd8, 0xea]
# (Loads, stores, INC, DEC, the shifts, arithmetic, compares and BIT of zero
# page; LDA and STA zp,X; and LDA and STA (zp),Y)
PROGRAM_ZP = [0xa5, 0xa6, 0xa4, 0x85, 0x86, 0x84, 0x85, 0x86, 0x84, 0xe6, 0xc6, 0x06, 0x26, 0x46, 0x66,
              0x25, 0x05, 0x45, 0x65, 0xe5, 0xc5, 0xe4, 0xc4, 0x24, 0xb5, 0x95, 0xb1, 0x91]
# (LDA and STA of an absolute address in zero page)
PROGRAM_ZP_ABS = [0xad, 0x8d]
PROGRAM_BRANCHES = [b[0] for b in BRANCHES]

def pointer_setup(rng):
    """Instructions (opcode, operand) that set the pointer at $72 to a byte
    of zero page that the programs use (so '(zp),Y' writes there)."""
    return [(0xa9, 0x70 + rng.randrange(4)), (0x85, 0x72), (0xa9, 0), (0x85, 0x73)]

def random_program(rng, slots=24):
    """A random program at $2000: a list of instructions (as lists of
    bytes), ending with RTS. Branch and jump targets are other
    instructions (filled in once the addresses are known)."""
    kinds = []
    for i in range(slots - 1):
        r = rng.random()
        if r < 0.25:
            kinds.append(("imm", rng.choice(PROGRAM_IMMEDIATE), rng.choice([0, 1, 2, 3, 7, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff, rng.randrange(256)])))
        elif r < 0.55:
            kinds.append(("implied", rng.choice(PROGRAM_IMPLIED)))
        elif r < 0.66:
            kinds.append(("zp", rng.choice(PROGRAM_ZP), 0x70 + rng.randrange(4)))
        elif r < 0.68:
            kinds.append(("zpabs", rng.choice(PROGRAM_ZP_ABS), 0x70 + rng.randrange(4)))
        elif r < 0.70:
            for op, operand in pointer_setup(rng):
                kinds.append(("imm" if op == 0xa9 else "zp", op, operand))
        elif r < 0.93:
            kinds.append(("branch", rng.choice(PROGRAM_BRANCHES), rng.randrange(slots)))
        elif r < 0.97:
            kinds.append(("jmp", 0x4c, rng.randrange(slots)))
        else:
            kinds.append(("rts", 0x60))
    kinds.append(("rts", 0x60))
    lengths = {"imm": 2, "implied": 1, "zp": 2, "zpabs": 3, "branch": 2, "jmp": 3, "rts": 1}
    addrs = []
    addr = 0x2000
    for k in kinds:
        addrs.append(addr)
        addr += lengths[k[0]]
    program = []
    for i, k in enumerate(kinds):
        if k[0] in ("imm", "zp"):
            program.append([k[1], k[2]])
        elif k[0] == "zpabs":
            program.append([k[1], k[2], 0])
        elif k[0] == "branch":
            program.append([k[1], (addrs[k[2]] - (addrs[i] + 2)) & 0xff])
        elif k[0] == "jmp":
            program.append([k[1], addrs[k[2]] & 0xff, addrs[k[2]] >> 8])
        else:
            program.append([k[1]])
    return program

def run(program_bytes, s, memory, steps=300):
    """Run the program (bytes at $2000) on the simple 6502 from the state s
    (changed as it runs), with 'memory' its memory (a Memory). Yields
    (address, branch taken or not, or None) after each instruction."""
    pc = 0x2000
    for _ in range(steps):
        op = program_bytes[pc - 0x2000]
        if op == 0x60:
            return
        if op == 0x4c:
            pc = program_bytes[pc - 0x2000 + 1] | program_bytes[pc - 0x2000 + 2] << 8
            yield None
            continue
        operand = program_bytes[pc - 0x2000 + 1] if pc - 0x2000 + 1 < len(program_bytes) else 0
        here = pc
        if op in PROGRAM_BRANCHES:
            flag, value = [(f, v) for b, f, v in BRANCHES if b == op][0]
            taken = s[flag] != value
            pc = (pc + 2 + (operand - 256 if operand & 0x80 else operand)) if taken else pc + 2
            yield here, taken
            continue
        if op in MEMORY_OPCODES:
            length = instruction_length(op)
            assert execute(op, program_bytes[pc - 0x2000 + 1:pc - 0x2000 + length], s, memory)
            pc += length
        elif op == 0x18:
            s['c'] = False
            pc += 1
        elif op == 0x38:
            s['c'] = True
            pc += 1
        elif op == 0xd8:
            s['d'] = False
            pc += 1
        elif op == 0xea:
            pc += 1
        else:
            assert step(op, operand, s)
            pc += 2 if op in PROGRAM_IMMEDIATE else 1
        yield here, None

def test_joining(rng, programs=150):
    import commands
    import os
    import session
    import tempfile
    count = 0
    for n in range(programs):
        program = random_program(rng)
        program_bytes = [b for instruction in program for b in instruction]
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(program_bytes))
            filename = f.name
        try:
            session.new_session(assembler="acme")
            commands.load(0x2000, filename, "6502")
            commands.entry(0x2000)
            cpu = session.current().cpu
            cpu.trace()
        finally:
            os.unlink(filename)
        for trial in range(30):
            s = {reg: rng.randrange(256) for reg in "axy"}
            for flag in "nvizc":
                s[flag] = rng.choice([False, True])
            s['d'] = False
            memory = Memory(rng, list(rng.randbytes(256)))
            for result in run(program_bytes, s, memory):
                if result is None:
                    continue
                here, taken = result
                state = cpu.cpu_states[here]
                if state is None:
                    fail("program %d: $%04x was run but not traced: %s" % (n, here, program_bytes))
                    break
                inputs = "program %d at $%04x (%s)" % (n, here, " ".join("%02x" % b for b in program_bytes))
                if taken is None or not taken:
                    if taken is False and state.always_branch:
                        fail("ALWAYS branch, but it isn't taken, at " + inputs)
                    if not state.always_branch:
                        check_disposition("joined", state.pessimistic, s, inputs)
                        check_zero_page("joined", state.pessimistic, memory, inputs)
                        count += 1
    return count


# 4. Subroutines

def random_program_with_subroutines(rng, subroutines=3, main_slots=14, sub_slots=9):
    """A random program at $2000: a main block and some subroutines, each
    a list of instructions ending with RTS, as one list of bytes. Each
    block's branches go within it; JSRs and JMPs (tail calls) go to the
    subroutines."""
    blocks = [main_slots] + [sub_slots] * subroutines
    kinds = []          # (block, kind...)
    for block, slots in enumerate(blocks):
        for i in range(slots - 1):
            r = rng.random()
            if r < 0.22:
                kinds.append((block, "imm", rng.choice(PROGRAM_IMMEDIATE), rng.choice([0, 1, 3, 7, 0x0f, 0x10, 0x80, 0xff, rng.randrange(256)])))
            elif r < 0.45:
                kinds.append((block, "implied", rng.choice(PROGRAM_IMPLIED)))
            elif r < 0.53:
                kinds.append((block, "zp", rng.choice(PROGRAM_ZP), 0x70 + rng.randrange(4)))
            elif r < 0.54:
                kinds.append((block, "abs", rng.choice(PROGRAM_ZP_ABS), 0x70 + rng.randrange(4)))
            elif r < 0.55:
                for op, operand in pointer_setup(rng):
                    kinds.append((block, "imm" if op == 0xa9 else "zp", op, operand))
            elif r < 0.68:
                kinds.append((block, "branch", rng.choice(PROGRAM_BRANCHES), rng.randrange(slots)))
            elif r < 0.80:
                kinds.append((block, "jsr", 0x20, 1 + rng.randrange(subroutines)))
            elif r < 0.88 and block > 0:
                # (A tail call)
                kinds.append((block, "jmp", 0x4c, 1 + rng.randrange(subroutines)))
            elif r < 0.91 and block > 0:
                # (Throwing away the return address, so the RTS returns to
                # the caller's caller)
                kinds.append((block, "implied", 0x68))
                kinds.append((block, "implied", 0x68))
            elif r < 0.93:
                kinds.append((block, "implied", rng.choice([0x48, 0x68, 0x08, 0x28])))      # PHA, PLA, PHP, PLP
            elif r < 0.95 and block > 0:
                # (Saving a register or the flags, and getting it back later
                # in the subroutine, perhaps through A)
                save, restore = rng.choice([([0x48], [0x68]), ([0x08], [0x28]), ([0x8a, 0x48], [0x68, 0xaa]),
                                            ([0x98, 0x48], [0x68, 0xa8]), ([0x8a, 0x48], [0x68, 0xa8])])
                for op in save:
                    kinds.append((block, "implied", op))
                kinds.append((block, "imm", rng.choice([0xa9, 0xa2, 0xa0]), rng.randrange(256)))
                for op in restore:
                    kinds.append((block, "implied", op))
            elif r < 0.96:
                # (Writing to the stack: TSX : STA $01xx,X)
                kinds.append((block, "implied", 0xba))
                kinds.append((block, "abs", 0x9d, 0x0101 + rng.randrange(4)))
            else:
                kinds.append((block, "rts", 0x60))
        kinds.append((block, "rts", 0x60))
    lengths = {"imm": 2, "implied": 1, "zp": 2, "branch": 2, "jmp": 3, "jsr": 3, "rts": 1, "abs": 3}
    addrs = []
    starts = {}
    addr = 0x2000
    index_in_block = []
    counts = collections.Counter()
    for k in kinds:
        if k[0] not in starts:
            starts[k[0]] = len(addrs)
        index_in_block.append(counts[k[0]])
        counts[k[0]] += 1
        addrs.append(addr)
        addr += lengths[k[1]]
    program = []
    for i, k in enumerate(kinds):
        block, kind = k[0], k[1]
        if kind in ("imm", "zp"):
            program += [k[2], k[3]]
        elif kind == "branch":
            target = addrs[starts[block] + k[3]]
            program += [k[2], (target - (addrs[i] + 2)) & 0xff]
        elif kind in ("jsr", "jmp"):
            target = addrs[starts[k[3]]]
            program += [k[2], target & 0xff, target >> 8]
        elif kind == "abs":
            program += [k[2], k[3] & 0xff, k[3] >> 8]
        else:
            program += [k[2]]
    return program

def run_with_stack(program_bytes, s, memory, steps=400):
    """Run the program (bytes at $2000) on the simple 6502 from the state s,
    with 'memory' its memory (a Memory), and a stack (page 1, from $ff).
    Yields (address, branch taken or None, JSR returned to or None) after
    each instruction; for a JSR that's returned from, the third is the
    JSR's address, with s as it is after the return."""
    sp = 0xff
    pc = 0x2000
    calls = []          # (the JSR's address, SP after its push)
    end = 0x2000 + len(program_bytes)
    def push(v):
        nonlocal sp
        memory[0x100 | sp] = v
        sp = (sp - 1) & 0xff
    def pull():
        nonlocal sp
        sp = (sp + 1) & 0xff
        return memory[0x100 | sp]
    for _ in range(steps):
        if not 0x2000 <= pc < end:
            return
        op = program_bytes[pc - 0x2000]
        operand = program_bytes[pc - 0x2000 + 1] if pc + 1 < end else 0
        here = pc
        if op == 0x60:
            lo = pull()
            hi = pull()
            pc = ((hi << 8 | lo) + 1) & 0xffff
            # A return to a call (perhaps an outer one, if the subroutine
            # pulled its own return address) is checked; any other RTS is a
            # jump that py8dis can't see (to an address pushed as data), so
            # the run stops there
            while calls and calls[-1][1] + 2 < sp:
                calls.pop()
            if calls and calls[-1][1] + 2 == sp and pc == calls[-1][0] + 3:
                yield here, None, calls.pop()[0]
                continue
            return
        if op == 0x20:
            target = operand | program_bytes[pc - 0x2000 + 2] << 8
            ret = pc + 2
            push(ret >> 8)
            push(ret & 0xff)
            calls.append((pc, sp))
            pc = target
            continue
        if op == 0x48:
            push(s['a'])
            pc += 1
            yield here, None, None
            continue
        if op == 0x68:
            s['a'] = pull()
            s['n'] = bool(s['a'] & 0x80)
            s['z'] = s['a'] == 0
            pc += 1
            yield here, None, None
            continue
        if op == 0x08:
            push(sum(1 << bit for bit, flag in ((7, 'n'), (6, 'v'), (3, 'd'), (2, 'i'), (1, 'z'), (0, 'c')) if s[flag]) | 0x30)
            pc += 1
            yield here, None, None
            continue
        if op == 0x28:
            p = pull()
            for bit, flag in ((7, 'n'), (6, 'v'), (3, 'd'), (2, 'i'), (1, 'z'), (0, 'c')):
                s[flag] = bool(p & (1 << bit))
            if s['d']:
                # (Decimal arithmetic isn't modelled)
                return
            pc += 1
            yield here, None, None
            continue
        if op == 0xba:
            s['x'] = sp
            s['n'] = bool(sp & 0x80)
            s['z'] = sp == 0
            pc += 1
            yield here, None, None
            continue
        if op == 0x4c:
            pc = operand | program_bytes[pc - 0x2000 + 2] << 8
            yield here, None, None
            continue
        if op in PROGRAM_BRANCHES:
            flag, value = [(f, v) for b, f, v in BRANCHES if b == op][0]
            taken = s[flag] != value
            pc = (pc + 2 + (operand - 256 if operand & 0x80 else operand)) if taken else pc + 2
            yield here, taken, None
            continue
        if op in MEMORY_OPCODES:
            length = instruction_length(op)
            assert execute(op, program_bytes[pc - 0x2000 + 1:pc - 0x2000 + length], s, memory)
            pc += length
        elif op == 0x18:
            s['c'] = False
            pc += 1
        elif op == 0x38:
            s['c'] = True
            pc += 1
        elif op == 0xd8:
            s['d'] = False
            pc += 1
        elif op == 0xea:
            pc += 1
        else:
            assert step(op, operand, s)
            pc += 2 if op in PROGRAM_IMMEDIATE else 1
        yield here, None, None

def test_sequences(rng):
    """Each compare (and some other instructions), followed by each 6502
    instruction tested here, then each branch, from random states: what's
    known after the branch must be so. (So that e.g. 'cmp #n : sec : bcs'
    is always tried: SEC changes the carry, so it no longer says anything
    about how the register compared.)"""
    import memorymanager
    import session
    s = session.new_session(assembler="acme")
    cpu = make_cpu("6502")
    s.cpu = cpu
    count = 0
    firsts = [0xc9, 0xe0, 0xc0, 0x29, 0xa9, 0x0a, 0xca]
    middles = [op for op, name in INSTRUCTIONS if name == "6502" and op not in DECIMAL_SENSITIVE]
    for first in firsts:
        for middle in middles:
            for branch in BRANCHES:
                for trial in range(6):
                    operands = (rng.randrange(256), rng.randrange(256))
                    s.memory.binary[0x2000:0x2006] = [first, operands[0], middle, operands[1], branch[0], 0x0a]
                    regs = {reg: random_set(rng) for reg in "axy"}
                    flags = {flag: random_flag(rng) for flag in "nvdizc"}
                    state = cpu.CpuState()
                    set_disposition(state.pessimistic, regs, flags)
                    set_disposition(state.optimistic, regs, flags)
                    for addr in (0x2000, 0x2002, 0x2004):
                        cpu.opcodes[s.memory.binary[addr]].update_cpu_state(memorymanager.BinaryAddr(addr), state)
                    inputs = "%02x #%02x then %02x #%02x then branch %02x" % (first, operands[0], middle, operands[1], branch[0])
                    for concrete in concrete_states(regs, flags, rng, 16):
                        step(first, operands[0], concrete)
                        step(middle, operands[1], concrete)
                        if concrete[branch[1]] == branch[2]:
                            if state.always_branch:
                                fail("ALWAYS branch, but it isn't taken, for " + inputs)
                            else:
                                check_disposition("sequence", state.pessimistic, concrete, inputs)
                                count += 1
    return count

# Programs for test_subroutines() that random ones rarely make: a tail
# call to a subroutine that changes X (so X after the call isn't the
# caller's), and a subroutine that throws away its return address (so its
# caller's call doesn't return where the JSR is)
#
#   main: ldx #5 : jsr sub_a : stx $70 : ldy #9 : jsr sub_c : sty $71 :
#         jsr sub_b : rts
#   sub_a: lda #1 : jmp sub_b
#   sub_b: ldx #7 : rts
#   sub_c: jsr sub_d : ldy #2 : rts
#   sub_d: pla : pla : ldy #3 : rts
#
# And registers and flags saved and got back (so they're as they were after
# the call), and saved values that are changed on the stack (so they aren't)
#
#   main: lda #5 : ldx #6 : jsr sub_a : sta $70 : stx $71 : jsr sub_b :
#         sta $72 : clc : jsr sub_c : bcs + : + jsr sub_d : sta $73 : rts
#   sub_a: pha : txa : pha : lda #1 : tax : pla : tax : pla : rts
#   sub_b: pha : jsr tamper : pla : rts
#   tamper: lda #9 : tsx : sta $0103,x : rts   (changes sub_b's saved A)
#   sub_c: php : sec : plp : rts
#   sub_d: pha : lda #3 : tsx : sta $0101,x : pla : rts
#
# And flags pulled that aren't the caller's (so they aren't as they were)
#
#   main: clc : jsr sub_e : clc : jsr sub_f : bcs + : + rts
#   sub_e: sec : php : plp : rts       (C is set after the call)
#   sub_f: lda #$c0 : pha : plp : rts  (the flags are $c0's bits)
#
# And a byte of zero page that the subroutine writes with a value that
# isn't known (so it isn't as it was before the call), and one it doesn't
# write (so it is)
#
#   main: lda #5 : sta $70 : sta $71 : jsr sub_g : lda $70 : ldx $71 : rts
#   sub_g: lda $80 : sta $70 : rts
#
# And bytes written by a subroutine that the subroutine calls, and by one it
# jumps to (a tail call)
#
#   main: lda #5 : sta $70 : sta $71 : jsr sub_h : lda $70 : ldx $71 :
#         jsr sub_j : rts
#   sub_h: jsr sub_i : jmp sub_j
#   sub_i: lda $80 : sta $70 : rts
#   sub_j: lda $81 : sta $71 : rts
FIXED_PROGRAMS = ["a2052012208670a009201a20847120172060a9014c1720a20760202020a002606868a00360",
                  "a905a206201c2085708671202620857218203320b00020372085736048"
                  "8a48a901aa68aa68604820" "2c20" "6860a909ba9d0301600838286048a903ba9d01016860",
                  "18200b2018200f20b0006038082860a9c0482860",
                  "a90585708571200e20a570a67160a580857060",
                  "a90585708571201120a570a671201c2060" "201720" "4c1c20" "a580857060" "a581857160"]

def test_subroutines(rng, programs=200):
    import commands
    import os
    import session
    import tempfile
    count = 0
    for n in range(len(FIXED_PROGRAMS) + programs):
        if n < len(FIXED_PROGRAMS):
            program_bytes = list(bytes.fromhex(FIXED_PROGRAMS[n]))
        else:
            program_bytes = random_program_with_subroutines(rng)
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(program_bytes))
            filename = f.name
        try:
            session.new_session(assembler="acme")
            commands.load(0x2000, filename, "6502")
            commands.entry(0x2000)
            cpu = session.current().cpu
            cpu.trace()
        finally:
            os.unlink(filename)
        inputs = "program %d (%s)" % (n, " ".join("%02x" % b for b in program_bytes))
        for trial in range(30):
            s = {reg: rng.randrange(256) for reg in "axy"}
            for flag in "nvizc":
                s[flag] = rng.choice([False, True])
            s['d'] = False
            memory = Memory(rng, list(rng.randbytes(256)))
            for here, taken, returned in run_with_stack(program_bytes, s, memory):
                if returned is not None:
                    # The state after the JSR, now that the call has returned
                    state = cpu.cpu_states[returned]
                    if state is not None:
                        check_disposition("after the call", state.pessimistic, s, "JSR at $%04x in %s" % (returned, inputs))
                        check_zero_page("after the call", state.pessimistic, memory, "JSR at $%04x in %s" % (returned, inputs))
                        count += 1
                    continue
                state = cpu.cpu_states[here]
                if state is None:
                    continue
                c = cpu.opcodes.get(program_bytes[here - 0x2000])
                if c is not None and c.mnemonic.lower() in ("rts", "jsr"):
                    continue
                if taken is False and state.always_branch:
                    fail("ALWAYS branch, but it isn't taken, at $%04x in %s" % (here, inputs))
                if not taken and not state.always_branch:
                    check_disposition("subroutines", state.pessimistic, s, "$%04x in %s" % (here, inputs))
                    check_zero_page("subroutines", state.pessimistic, memory, "$%04x in %s" % (here, inputs))
                    count += 1
    return count


def main():
    rng = random.Random(6502)
    test_valuesets(rng)
    count = test_cpu_state(rng)
    count += test_zero_page(rng)
    count += test_examples()
    count += test_joining(rng)
    count += test_sequences(rng)
    count += test_subroutines(rng)
    if failures:
        print("%d failed" % len(failures))
        sys.exit(1)
    print("CPU state tests: all passed (%d CPU states checked)" % count)

if __name__ == "__main__":
    main()
