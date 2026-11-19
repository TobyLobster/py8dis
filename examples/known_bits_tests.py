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

3. Joining at labels (see Cpu6502.join_states_at_labels()): random
   programs of the instructions above, with loads, stores, conditional
   branches (forwards and backwards, so with loops) and jumps, are traced by
   py8dis, then run on the simple 6502 from random states (with D clear) and
   random memory. At each instruction run, what py8dis says it knows for
   certain after it must be so (after a branch, only when it isn't taken,
   and a branch it says is always taken must be).

4. What subroutines leave behind (see Cpu6502.subroutine_summaries()):
   random programs with subroutines, which call each other, jump to each
   other (tail calls), push and pull A and the flags (sometimes unevenly,
   so that an RTS goes somewhere else), save registers and flags on the
   stack and get them back (perhaps through A), and write to the stack
   (TSX : STA $01xx,X, which can change what was saved), are traced and run on the simple 6502 with a
   real stack. What py8dis says it knows is checked as in 3, and what it
   says it knows after a JSR is checked when the call returns. A run stops
   at an RTS that doesn't return to a call (it's a jump to an address that
   was pushed, which py8dis can't follow).

The tests are randomised with a fixed seed, so they're the same each run.

Usage: ./known_bits_tests.py   (exits with 1 if any fail)
"""

import collections
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


# 3. Joining at labels

# The instructions of the random programs: (opcode, length), by kind
PROGRAM_IMMEDIATE = [0xa9, 0xa2, 0xa0, 0x29, 0x09, 0x49, 0x69, 0xe9, 0xc9, 0xe0, 0xc0]
PROGRAM_IMPLIED = [0x0a, 0x2a, 0x4a, 0x6a, 0xe8, 0xca, 0xc8, 0x88, 0xaa, 0x8a, 0xa8, 0x98, 0x18, 0x38, 0xd8, 0xea]
PROGRAM_ZP = [0xa5, 0xa6, 0xa4, 0x85, 0x86, 0x84]          # LDA/LDX/LDY/STA/STX/STY zp
PROGRAM_BRANCHES = [b[0] for b in BRANCHES]

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
        elif r < 0.7:
            kinds.append(("zp", rng.choice(PROGRAM_ZP), 0x70 + rng.randrange(4)))
        elif r < 0.93:
            kinds.append(("branch", rng.choice(PROGRAM_BRANCHES), rng.randrange(slots)))
        elif r < 0.97:
            kinds.append(("jmp", 0x4c, rng.randrange(slots)))
        else:
            kinds.append(("rts", 0x60))
    kinds.append(("rts", 0x60))
    lengths = {"imm": 2, "implied": 1, "zp": 2, "branch": 2, "jmp": 3, "rts": 1}
    addrs = []
    addr = 0x2000
    for k in kinds:
        addrs.append(addr)
        addr += lengths[k[0]]
    program = []
    for i, k in enumerate(kinds):
        if k[0] in ("imm", "zp"):
            program.append([k[1], k[2]])
        elif k[0] == "branch":
            program.append([k[1], (addrs[k[2]] - (addrs[i] + 2)) & 0xff])
        elif k[0] == "jmp":
            program.append([k[1], addrs[k[2]] & 0xff, addrs[k[2]] >> 8])
        else:
            program.append([k[1]])
    return program

def run(program_bytes, s, memory, steps=300):
    """Run the program (bytes at $2000) on the simple 6502 from the state s
    (changed as it runs), with 'memory' its zero page. Yields (address,
    branch taken or not, or None) after each instruction."""
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
        if op in (0xa5, 0xa6, 0xa4):
            reg = {0xa5: 'a', 0xa6: 'x', 0xa4: 'y'}[op]
            s[reg] = memory[operand]
            s['n'] = bool(s[reg] & 0x80)
            s['z'] = s[reg] == 0
            pc += 2
        elif op in (0x85, 0x86, 0x84):
            memory[operand] = s[{0x85: 'a', 0x86: 'x', 0x84: 'y'}[op]]
            pc += 2
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
            memory = [rng.randrange(256) for _ in range(256)]
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
            elif r < 0.55:
                kinds.append((block, "zp", rng.choice(PROGRAM_ZP), 0x70 + rng.randrange(4)))
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
    with a stack (page 1, from $ff) and zero page 'memory'. Yields
    (address, branch taken or None, JSR returned to or None) after each
    instruction; for a JSR that's returned from, the third is the JSR's
    address, with s as it is after the return."""
    stack = [0] * 256
    sp = 0xff
    pc = 0x2000
    calls = []          # (the JSR's address, SP after its push)
    end = 0x2000 + len(program_bytes)
    def push(v):
        nonlocal sp
        stack[sp] = v
        sp = (sp - 1) & 0xff
    def pull():
        nonlocal sp
        sp = (sp + 1) & 0xff
        return stack[sp]
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
        if op == 0x9d:
            address = (operand | program_bytes[pc - 0x2000 + 2] << 8) + s['x']
            if 0x100 <= address <= 0x1ff:
                stack[address & 0xff] = s['a']
            elif address < 0x100:
                memory[address] = s['a']
            pc += 3
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
        if op in (0xa5, 0xa6, 0xa4):
            reg = {0xa5: 'a', 0xa6: 'x', 0xa4: 'y'}[op]
            s[reg] = memory[operand]
            s['n'] = bool(s[reg] & 0x80)
            s['z'] = s[reg] == 0
            pc += 2
        elif op in (0x85, 0x86, 0x84):
            memory[operand] = s[{0x85: 'a', 0x86: 'x', 0x84: 'y'}[op]]
            pc += 2
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
                    regs = {reg: random_known_bits(rng) for reg in "axy"}
                    ranges = {reg: random_range(rng, regs[reg]) for reg in "axy"}
                    flags = {flag: random_flag(rng) for flag in "nvdizc"}
                    state = cpu.CpuState()
                    set_disposition(state.pessimistic, regs, flags, ranges)
                    set_disposition(state.optimistic, regs, flags, ranges)
                    for addr in (0x2000, 0x2002, 0x2004):
                        cpu.opcodes[s.memory.binary[addr]].update_cpu_state(memorymanager.BinaryAddr(addr), state)
                    inputs = "%02x #%02x then %02x #%02x then branch %02x" % (first, operands[0], middle, operands[1], branch[0])
                    for concrete in concrete_states(regs, flags, ranges, rng, 16):
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
FIXED_PROGRAMS = ["a2052012208670a009201a20847120172060a9014c1720a20760202020a002606868a00360",
                  "a905a206201c2085708671202620857218203320b00020372085736048"
                  "8a48a901aa68aa68604820" "2c20" "6860a909ba9d0301600838286048a903ba9d01016860",
                  "18200b2018200f20b0006038082860a9c0482860"]

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
            memory = [rng.randrange(256) for _ in range(256)]
            for here, taken, returned in run_with_stack(program_bytes, s, memory):
                if returned is not None:
                    # The state after the JSR, now that the call has returned
                    state = cpu.cpu_states[returned]
                    if state is not None:
                        check_disposition("after the call", state.pessimistic, s, "JSR at $%04x in %s" % (returned, inputs))
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
                    count += 1
    return count


def main():
    rng = random.Random(6502)
    test_knownbits(rng)
    test_precision()
    count = test_cpu_state(rng)
    count += test_joining(rng)
    count += test_sequences(rng)
    count += test_subroutines(rng)
    if failures:
        print("%d failed" % len(failures))
        sys.exit(1)
    print("Known bits tests: all passed (%d CPU states checked)" % count)

if __name__ == "__main__":
    main()
