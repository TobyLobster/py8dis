#!/usr/bin/env python3
"""
Known bits tests

Tests for what py8dis knows about the 6502's registers bit by bit (see
py8dis/knownbits.py and the CPU state in py8dis/cpu6502.py), run by
run_tests.py -c when all the tests are run.

1. The functions in knownbits.py: for random inputs with some bits known,
   every bit a function says is known must be right for every value the
   inputs could be (all of them, or a random 300 if there are more), and
   for inputs that are wholly known, the result must be wholly known. Some
   results that py8dis's comments rely on must be known, e.g. that A - $10
   always borrows after 'and #$0f'.

2. The CPU state (each register's known bits and its range, and the
   flags): for each instruction whose update works on known bits
   (AND, ORA, EOR, ADC, SBC, CMP, CPX and CPY with an immediate operand;
   ASL, LSR, ROL and ROR of A and of memory; INX, DEX, INY, DEY; the
   transfers and immediate loads; the 65C02's INC A, DEC A and BIT #imm;
   the 6510's ANC and ALR), from a random state with some bits and flags
   known, each register bit and flag py8dis says it knows afterwards must
   be what a simple 6502 (below) gives, for every state that agrees with
   what was known before (a random 64 of them). The same is done for each
   of those instructions followed by a conditional branch that isn't taken,
   where the branch says something about the result (e.g. A is 1 after
   'and #1 : beq skip'), sometimes with another instruction between them
   (e.g. 'cmp #5 : lda #9 : bcs', where what CMP said about A no longer
   holds).

The tests are randomised with a fixed seed, so they're the same each run.

Usage: ./known_bits_tests.py   (exits with 1 if any fail)
"""

import random
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"
sys.path.insert(0, str(PY8DIS_DIR))

import knownbits

failures = []

def fail(message):
    failures.append(message)
    if len(failures) <= 20:
        print("FAIL: " + message)


# 1. knownbits.py

def random_known_bits(rng):
    """A random (known, bits) pair: sometimes nothing or everything known."""
    choice = rng.random()
    if choice < 0.1:
        return knownbits.UNKNOWN
    if choice < 0.3:
        return knownbits.exact(rng.randrange(256))
    known = rng.randrange(256)
    return (known, rng.randrange(256) & known)

def values(kb, rng, limit=300):
    """The values kb could be: all of them, or a random 'limit' of them."""
    known, bits = kb
    unknown = [n for n in range(8) if not (known >> n) & 1]
    if 2 ** len(unknown) <= limit:
        result = []
        for i in range(2 ** len(unknown)):
            v = bits
            for j, n in enumerate(unknown):
                if (i >> j) & 1:
                    v |= 1 << n
            result.append(v)
        return result
    return [bits | (rng.randrange(256) & ~known & 0xff) for _ in range(limit)]

def random_carry(rng):
    return rng.choice([None, True, False])

def carries(c):
    return [False, True] if c is None else [c]

def check_kb(name, kb, value, inputs):
    """kb must agree with the actual value."""
    known, bits = kb
    if bits & ~known:
        fail("%s: bits %02x outside known %02x for %s" % (name, bits, known, inputs))
    elif (value & known) != bits:
        fail("%s: says %s, but it's %02x, for %s" % (name, knownbits.show_bits(kb), value, inputs))

def check_flag(name, claimed, actual, inputs):
    if claimed is not None and bool(claimed) != bool(actual):
        fail("%s: says %s, but it's %s, for %s" % (name, claimed, actual, inputs))

def test_knownbits(rng):
    for _ in range(3000):
        a = random_known_bits(rng)
        b = random_known_bits(rng)
        c = random_carry(rng)
        n = rng.randrange(8)
        inputs = (knownbits.show_bits(a), knownbits.show_bits(b), c)
        and_r = knownbits.and_(a, b)
        or_r = knownbits.or_(a, b)
        eor_r = knownbits.eor(a, b)
        add_r, add_c = knownbits.add(a, b, c)
        sub_r, sub_c = knownbits.subtract(a, b, c)
        asl_r, asl_c = knownbits.asl(a)
        lsr_r, lsr_c = knownbits.lsr(a)
        rol_r, rol_c = knownbits.rol(a, c)
        ror_r, ror_c = knownbits.ror(a, c)
        n_r = knownbits.n_flag(a)
        z_r = knownbits.z_flag(a)
        lo, hi = knownbits.bounds(a)
        for av in values(a, rng, 40):
            check_flag("n_flag", n_r, av & 0x80, inputs)
            check_flag("z_flag", z_r, av == 0, inputs)
            if not lo <= av <= hi:
                fail("bounds: %02x outside %02x-%02x" % (av, lo, hi))
            if not knownbits.could_be(a, av):
                fail("could_be: %02x for %s" % (av, inputs))
            for cv in carries(c):
                check_kb("asl", asl_r, (av << 1) & 0xff, inputs)
                check_flag("asl carry", asl_c, av & 0x80, inputs)
                check_kb("lsr", lsr_r, av >> 1, inputs)
                check_flag("lsr carry", lsr_c, av & 1, inputs)
                check_kb("rol", rol_r, ((av << 1) | cv) & 0xff, inputs)
                check_flag("rol carry", rol_c, av & 0x80, inputs)
                check_kb("ror", ror_r, (av >> 1) | (0x80 if cv else 0), inputs)
                check_flag("ror carry", ror_c, av & 1, inputs)
                check_kb("with_bit", knownbits.with_bit(a, n, cv), (av & ~(1 << n)) | ((1 << n) if cv else 0), inputs)
                for bv in values(b, rng, 8):
                    check_kb("and", and_r, av & bv, inputs)
                    check_kb("or", or_r, av | bv, inputs)
                    check_kb("eor", eor_r, av ^ bv, inputs)
                    total = av + bv + cv
                    check_kb("add", add_r, total & 0xff, inputs)
                    check_flag("add carry", add_c, total > 0xff, inputs)
                    total = av + (~bv & 0xff) + cv
                    check_kb("subtract", sub_r, total & 0xff, inputs)
                    check_flag("subtract carry", sub_c, total > 0xff, inputs)
        # Wholly known inputs give wholly known results
        if knownbits.is_exact(a) and knownbits.is_exact(b) and c is not None:
            for name, r, carry in (("add", add_r, add_c), ("subtract", sub_r, sub_c)):
                if not knownbits.is_exact(r) or carry is None:
                    fail("%s: not exact for exact inputs %s" % (name, inputs))
            for name, r in (("and", and_r), ("or", or_r), ("eor", eor_r), ("asl", asl_r), ("lsr", lsr_r), ("rol", rol_r), ("ror", ror_r)):
                if not knownbits.is_exact(r):
                    fail("%s: not exact for exact inputs %s" % (name, inputs))


def test_precision():
    """Some results that must be known (not just right): those that
    py8dis's comments rely on."""
    low_nibble = (0xf0, 0x00)                       # After 'and #$0f'
    cases = [
        # (A at most $0f) - $10: always borrows, and isn't 0
        ("subtract", knownbits.subtract(low_nibble, knownbits.exact(0x10), True), ((0x00, 0x00), False), True),
        # (A at most $0f) + $f0 with carry clear: never carries, top nibble $f
        ("add", knownbits.add(low_nibble, knownbits.exact(0xf0), False), ((0xf0, 0xf0), False), False),
        # (A even) + 1: bit 0 set, the rest as they were, no carry
        ("add", knownbits.add((0x01, 0x00), knownbits.exact(1), False), ((0x01, 0x01), False), False),
        # (A at least $80) + $80: always carries
        ("add", knownbits.add((0x80, 0x80), knownbits.exact(0x80), False), ((0x80, 0x00), True), False),
    ]
    for name, (result, carry), ((want_known, want_bits), want_carry), want_nonzero in cases:
        if (result[0] & want_known) != want_known or (result[1] & want_known) != want_bits or carry != want_carry:
            fail("precision: %s gave %s, carry %s" % (name, knownbits.show_bits(result), carry))
        if want_nonzero and knownbits.z_flag(result) is not False:
            fail("precision: %s gave %s, which could be 0" % (name, knownbits.show_bits(result)))


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
                                        0xa9, 0xa2, 0xa0)] + \
               [(op, "65C02") for op in (0x1a, 0x3a, 0x89)] + [(op, "6510") for op in (0x0b, 0x4b)]

# The branches: (opcode, flag, the value the flag has if it isn't taken)
BRANCHES = [(0x10, 'n', True), (0x30, 'n', False), (0x50, 'v', True), (0x70, 'v', False),
            (0x90, 'c', True), (0xb0, 'c', False), (0xd0, 'z', True), (0xf0, 'z', False)]

# The z_from inferences (from BNE) assume binary arithmetic, as py8dis
# always has: so ADC and SBC are followed by a branch only with D clear
DECIMAL_SENSITIVE = (0x69, 0xe9)

def random_flag(rng):
    return rng.choice([None, None, True, False])

def make_cpu(name):
    import cpu6502
    import cpu65C02
    import cpu6510
    return {"6502": cpu6502.Cpu6502, "65C02": cpu65C02.Cpu65C02, "6510": cpu6510.Cpu6510}[name]()

def random_range(rng, kb):
    """A random range for a register with known bits kb: often what the
    bits allow, otherwise narrower."""
    lo, hi = knownbits.bounds(kb)
    if rng.random() < 0.5:
        return lo, hi
    a = rng.randint(lo, hi)
    b = rng.randint(lo, hi)
    return min(a, b), max(a, b)

def set_disposition(disposition, regs, flags, ranges):
    for reg in "axy":
        disposition[reg].set_range(regs[reg], *ranges[reg])
    for flag in "nvdizc":
        disposition[flag] = flags[flag]

def check_disposition(name, disposition, s, inputs):
    """What the disposition says it knows must be what s (the 6502's
    state) is."""
    for reg in "axy":
        check_kb(name + " " + reg.upper(), disposition[reg].known_bits, s[reg], inputs)
        r = disposition[reg]
        if not r.lo <= s[reg] <= r.hi:
            fail("%s %s: says %d-%d, but it's %d, for %s" % (name, reg.upper(), r.lo, r.hi, s[reg], inputs))
    for flag in "nvdizc":
        value = disposition[flag]
        if value == 'pending':
            continue
        check_flag(name + " flag " + flag, value, s[flag], inputs)

def concrete_states(regs, flags, ranges, rng, count=64):
    """Random 6502 states that agree with what's known (the known bits and
    the ranges of the registers, and the flags)."""
    choices = {}
    for reg in "axy":
        known, bits = regs[reg]
        lo, hi = ranges[reg]
        choices[reg] = [v for v in range(lo, hi + 1) if (v & known) == bits]
        if not choices[reg]:
            return []
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
            regs = {reg: random_known_bits(rng) for reg in "axy"}
            ranges = {reg: random_range(rng, regs[reg]) for reg in "axy"}
            flags = {flag: random_flag(rng) for flag in "nvdizc"}
            if with_branch and opcode in DECIMAL_SENSITIVE:
                flags['d'] = False
            state = cpu.CpuState()
            set_disposition(state.pessimistic, regs, flags, ranges)
            set_disposition(state.optimistic, regs, flags, ranges)
            cpu.opcodes[opcode].update_cpu_state(memorymanager.BinaryAddr(0x2000), state)
            after_instruction = state.copy()
            if middle:
                cpu.opcodes[middle[0]].update_cpu_state(memorymanager.BinaryAddr(0x2002), state)
            if with_branch:
                cpu.opcodes[branch[0]].update_cpu_state(memorymanager.BinaryAddr(0x2004), state)
            inputs = "opcode %02x #%02x%s%s from A:%s %s X:%s %s Y:%s %s %s" % (
                opcode, operand, (" then %02x #%02x" % middle) if middle else "", (" then branch %02x" % branch[0]) if with_branch else "",
                knownbits.show_bits(regs['a']), ranges['a'], knownbits.show_bits(regs['x']), ranges['x'],
                knownbits.show_bits(regs['y']), ranges['y'],
                "".join("-" if flags[f] is None else (f.upper() if flags[f] else f) for f in "nvdizc"))
            for concrete in concrete_states(regs, flags, ranges, rng):
                if not step(opcode, operand, concrete):
                    # (Decimal ADC or SBC: py8dis mustn't claim anything about the result)
                    d = after_instruction.pessimistic
                    if d['a'].known != 0 or any(d[f] not in (None, 'pending') for f in "nvzc"):
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


def main():
    rng = random.Random(6502)
    test_knownbits(rng)
    test_precision()
    count = test_cpu_state(rng)
    if failures:
        print("%d failed" % len(failures))
        sys.exit(1)
    print("Known bits tests: all passed (%d CPU states checked)" % count)

if __name__ == "__main__":
    main()
