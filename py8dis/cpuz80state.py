"""
What's known about the Z80's registers and flags (see CpuState), and how each
instruction changes it (see update_state()).

A register is an 8 bit number, or None if it's not known; a flag is True or
False, or None. Memory isn't tracked, so a value read from memory (or an I/O
port) isn't known. Undocumented flag bits 3 and 5, R, the interrupt mode and
the interrupt flip-flops aren't tracked.
"""

import utils


# The registers: the main set, the index registers' halves, SP (16 bits), I,
# then the alternate set (swapped by EX AF,AF' and EXX)
MAIN_REGISTERS      = ("a", "b", "c", "d", "e", "h", "l")
REGISTERS           = MAIN_REGISTERS + ("ixh", "ixl", "iyh", "iyl", "sp", "i")
ALTERNATE_REGISTERS = tuple(r + "'" for r in MAIN_REGISTERS)

# The flags: S (sign), Z (zero), H (half carry, 'hc'), P/V (parity or
# overflow, 'pv'), N (subtract) and C (carry, 'cy')
FLAGS           = ("s", "z", "hc", "pv", "n", "cy")
ALTERNATE_FLAGS = tuple(f + "'" for f in FLAGS)

ALL = REGISTERS + FLAGS + ALTERNATE_REGISTERS + ALTERNATE_FLAGS


class CpuState:
    """What's known for certain about the registers and flags (see the module
    docs): CpuState()["a"] is A's value, or None if it's not known."""

    REGISTERS = REGISTERS + ALTERNATE_REGISTERS
    FLAGS     = FLAGS + ALTERNATE_FLAGS

    def __init__(self):
        self.clear()

    def clear(self, *, pessimistic_only=False):
        """Forget everything. (There's only one state for the Z80, so
        'pessimistic_only' makes no difference.)"""
        self.values = dict.fromkeys(ALL)

        # True after an instruction the following instruction can't be
        # reached from (e.g. JP or RET), so that it starts with nothing known
        self.block_end = False

    def copy(self):
        result = type(self).__new__(type(self))
        result.values = dict(self.values)
        result.block_end = self.block_end
        return result

    def __getitem__(self, key):
        return self.values[key]

    def __setitem__(self, key, value):
        assert key in self.values
        self.values[key] = value

    def show(self):
        """The CPU state, for config.set_show_cpu_state(True), e.g.
        'A:41 BC:12-- DE:---- HL:---- IX:---- IY:---- SP:---- sZh-nc': each
        register (or pair) in hex ('--' for a byte that's not known), then
        each flag (S, Z, H, P/V, N, C) as an upper case letter if set, lower
        case if clear, or '-' if not known. (The alternate set and I aren't
        shown, but are in the JSON.)"""
        def byte(name):
            v = self.values[name]
            return "--" if v is None else utils.plainhex2(v)
        def flag(name, letter):
            v = self.values[name]
            return "-" if v is None else (letter.upper() if v else letter)
        sp = self.values["sp"]
        return "A:%s BC:%s%s DE:%s%s HL:%s%s IX:%s%s IY:%s%s SP:%s %s" % (
            byte("a"), byte("b"), byte("c"), byte("d"), byte("e"), byte("h"), byte("l"),
            byte("ixh"), byte("ixl"), byte("iyh"), byte("iyl"),
            "----" if sp is None else utils.plainhex4(sp),
            "".join(flag(name, letter) for name, letter in zip(FLAGS, "szhpnc")))


def _parity(value):
    """True if an 8 bit value has an even number of bits set."""
    return bin(value).count("1") % 2 == 0

def _signed8(value):
    return value - 0x100 if value >= 0x80 else value

# The 8 bit registers as the opcodes number them (6 is (HL), in memory)
R = ("b", "c", "d", "e", "h", "l", None, "a")

# The condition codes, as (flag, value when the condition is true)
CONDITIONS = (("z", False), ("z", True), ("cy", False), ("cy", True),
              ("pv", False), ("pv", True), ("s", False), ("s", True))


class _Machine:
    """Runs one instruction on a CpuState, with HL replaced by IX or IY
    (index "ix" or "iy") after a DD or FD prefix."""

    def __init__(self, state, index=None):
        self.state = state
        self.index = index

    # Registers

    def reg_name(self, i, halves=True):
        """The name of 8 bit register i (None for (HL) or (IX+d)), with IXH
        or IXL for H or L after a prefix (unless not 'halves')."""
        if halves and self.index and i in (4, 5):
            return self.index + "hl"[i - 4]
        return R[i]

    def get8(self, i, halves=True):
        name = self.reg_name(i, halves)
        return None if name is None else self.state[name]

    def set8(self, i, value, halves=True):
        name = self.reg_name(i, halves)
        if name is not None:
            self.state[name] = None if value is None else value & 0xff

    def pair_names(self, p, af=False):
        """The names of register pair p's high and low bytes: BC, DE, HL (or
        IX or IY after a prefix), then SP (or AF if 'af', for PUSH and POP)."""
        if p == 2:
            return (self.index + "h", self.index + "l") if self.index else ("h", "l")
        return (("b", "c"), ("d", "e"), None, ("a", None) if af else "sp")[p]

    def get16(self, p):
        names = self.pair_names(p)
        if names == "sp":
            return self.state["sp"]
        hi, lo = self.state[names[0]], self.state[names[1]]
        return None if hi is None or lo is None else (hi << 8) | lo

    def set16(self, p, value):
        names = self.pair_names(p)
        if names == "sp":
            self.state["sp"] = None if value is None else value & 0xffff
        elif value is None:
            self.state[names[0]] = self.state[names[1]] = None
        else:
            self.state[names[0]] = (value >> 8) & 0xff
            self.state[names[1]] = value & 0xff

    def forget_pair(self, names):
        for name in names:
            self.state[name] = None

    # Flags

    def set_flags(self, **flags):
        for name, value in flags.items():
            self.state[name] = None if value is None else bool(value)

    def set_szp(self, value, parity=True):
        """S, Z and (if 'parity') P/V for an 8 bit result (None if not
        known)."""
        if value is None:
            self.set_flags(s=None, z=None)
            if parity:
                self.set_flags(pv=None)
        else:
            self.set_flags(s=value & 0x80, z=value == 0)
            if parity:
                self.set_flags(pv=_parity(value))

    # Instructions

    def alu(self, op, value, value_is_a=False):
        """ADD, ADC, SUB, SBC, AND, XOR, OR or CP (op 0 to 7) of A with
        'value' (None if not known; 'value_is_a' if it's A itself)."""
        state = self.state
        a = state["a"]
        if op in (4, 5, 6):
            # AND, XOR, OR: the carry and N are cleared, H is set by AND
            self.set_flags(cy=False, n=False, hc=op == 4)
            if value_is_a and op == 5:
                result = 0                                  # (XOR A is 0)
            elif value_is_a:
                result = a                                  # (AND A and OR A leave A)
            elif a is None or value is None:
                result = None
            else:
                result = (a & value, a ^ value, a | value)[op - 4]
            state["a"] = result
            self.set_szp(result)
            return

        subtract = op in (2, 3, 7)
        carry_in = 0
        if op in (1, 3):
            carry_in = None if state["cy"] is None else int(state["cy"])
        if value_is_a and op in (2, 7):
            # (SUB A and CP A are 0, whatever A is)
            a = value = 0
        self.set_flags(n=subtract)
        if a is None or value is None or carry_in is None:
            if op != 7:
                state["a"] = None
            self.set_flags(s=None, z=None, hc=None, pv=None, cy=None)
            return
        if subtract:
            result = a - value - carry_in
            hc = (a & 0xf) - (value & 0xf) - carry_in < 0
            overflow = ((a ^ value) & (a ^ result) & 0x80) != 0
            cy = result < 0
        else:
            result = a + value + carry_in
            hc = (a & 0xf) + (value & 0xf) + carry_in > 0xf
            overflow = (~(a ^ value) & (a ^ result) & 0x80) != 0
            cy = result > 0xff
        result &= 0xff
        if op != 7:
            state["a"] = result
        self.set_szp(result, parity=False)
        self.set_flags(hc=hc, pv=overflow, cy=cy)

    def inc_dec(self, value, dec):
        """INC or DEC of an 8 bit value (None if not known), setting the
        flags (except the carry, which isn't changed). Returns the result."""
        self.set_flags(n=dec)
        if value is None:
            self.set_flags(s=None, z=None, hc=None, pv=None)
            return None
        result = (value + (-1 if dec else 1)) & 0xff
        self.set_szp(result, parity=False)
        if dec:
            self.set_flags(hc=(result & 0xf) == 0xf, pv=result == 0x7f)
        else:
            self.set_flags(hc=(result & 0xf) == 0, pv=result == 0x80)
        return result

    def rotate(self, op, value):
        """RLC, RRC, RL, RR, SLA, SRA, SLL or SRL (op 0 to 7, as CB
        numbers them) of a value (None if not known), setting the flags.
        Returns the result."""
        self.set_flags(hc=False, n=False)
        cy_in = self.state["cy"]
        if value is None or (op in (2, 3) and cy_in is None):
            self.set_flags(s=None, z=None, pv=None, cy=None)
            return None
        if op == 0:
            cy, result = value >> 7, (value << 1) | (value >> 7)
        elif op == 1:
            cy, result = value & 1, (value >> 1) | ((value & 1) << 7)
        elif op == 2:
            cy, result = value >> 7, (value << 1) | int(cy_in)
        elif op == 3:
            cy, result = value & 1, (value >> 1) | (int(cy_in) << 7)
        elif op == 4:
            cy, result = value >> 7, value << 1
        elif op == 5:
            cy, result = value & 1, (value >> 1) | (value & 0x80)
        elif op == 6:
            cy, result = value >> 7, (value << 1) | 1
        else:
            cy, result = value & 1, value >> 1
        result &= 0xff
        self.set_szp(result)
        self.set_flags(cy=cy)
        return result

    def bit(self, b, value):
        """BIT b of a value (None if not known)."""
        self.set_flags(hc=True, n=False)
        if value is None:
            self.set_flags(z=None, pv=None, s=None if b == 7 else False)
            return
        result = value & (1 << b)
        self.set_flags(z=result == 0, pv=result == 0, s=result & 0x80)

    def add16(self, p_dest, value, carry=None, subtract=False):
        """ADD (flags H, N and C), or ADC or SBC (all the flags, with
        'carry' as the carry in) of a 16 bit value to register pair
        p_dest."""
        state = self.state
        full = carry is not None
        dest = self.get16(p_dest)
        carry_in = 0
        if full:
            carry_in = None if state["cy"] is None else int(state["cy"])
        self.set_flags(n=subtract)
        if dest is None or value is None or carry_in is None:
            self.set16(p_dest, None)
            self.set_flags(hc=None, cy=None)
            if full:
                self.set_flags(s=None, z=None, pv=None)
            return
        if subtract:
            result = dest - value - carry_in
            hc = (dest & 0xfff) - (value & 0xfff) - carry_in < 0
            overflow = ((dest ^ value) & (dest ^ result) & 0x8000) != 0
            cy = result < 0
        else:
            result = dest + value + carry_in
            hc = (dest & 0xfff) + (value & 0xfff) + carry_in > 0xfff
            overflow = (~(dest ^ value) & (dest ^ result) & 0x8000) != 0
            cy = result > 0xffff
        result &= 0xffff
        self.set16(p_dest, result)
        self.set_flags(hc=hc, cy=cy)
        if full:
            self.set_flags(s=result & 0x8000, z=result == 0, pv=overflow)

    def daa(self):
        state = self.state
        a, n, hc, cy = state["a"], state["n"], state["hc"], state["cy"]
        if a is None or n is None or hc is None or cy is None:
            state["a"] = None
            self.set_flags(s=None, z=None, hc=None, pv=None, cy=None)
            return
        correction = 0
        if hc or (a & 0xf) > 9:
            correction |= 0x06
        if cy or a > 0x99:
            correction |= 0x60
            cy = True
        if n:
            hc = hc and (a & 0xf) < 6
            result = (a - correction) & 0xff
        else:
            hc = (a & 0xf) > 9
            result = (a + correction) & 0xff
        state["a"] = result
        self.set_szp(result)
        self.set_flags(hc=hc, cy=cy)

    def condition(self, y, met):
        """Record that condition y is (if 'met') or isn't met."""
        flag, value = CONDITIONS[y]
        self.state[flag] = value if met else not value

    def swap(self, names):
        for name in names:
            self.state[name], self.state[name + "'"] = self.state[name + "'"], self.state[name]


def update_state(state, key, operands, next_addr=None):
    """Update what's known about the CPU (a CpuState) for the instruction
    whose opcode is 'key' (as cpuz80.opcode_specs() gives it: its prefix and
    opcode bytes) with the given bytes after its opcode (for DD CB d op and
    FD CB d op, the displacement), so that it's what's known once the
    instruction has run, assuming it continues to the next instruction (a
    conditional jump or return not taken, or a repeated block instruction
    finished). 'next_addr' is the runtime address of the next instruction,
    if known: a conditional jump to it says nothing about its condition."""

    if key[0] == 0xcb:
        _cb(_Machine(state), key[1], memory=key[1] & 7 == 6)
    elif key[0] == 0xed:
        _ed(_Machine(state), key[1])
    elif len(key) == 3:
        # DD CB d op or FD CB d op: on (IX+d) or (IY+d), in memory, also
        # copying the result to a register (except for BIT), unless its
        # register field is 6
        _cb(_Machine(state), key[2], memory=True)
        if key[2] >> 6 != 1 and key[2] & 7 != 6:
            state[R[key[2] & 7]] = None
    elif key[0] in (0xdd, 0xfd) and len(key) == 1:
        pass                                # (A prefix with no effect)
    elif key[0] in (0xdd, 0xfd):
        _main(_Machine(state, "ix" if key[0] == 0xdd else "iy"), key[1], operands, next_addr)
    else:
        _main(_Machine(state), key[0], operands, next_addr)


def _main(m, op, operands, next_addr):
    """An unprefixed opcode (or, with m.index, after DD or FD), with the
    bytes after it (for (IX+d), starting with the displacement: an immediate
    byte is always the last, and a 16 bit value never follows one)."""
    state = m.state
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    p, q = y >> 1, y & 1
    imm8 = operands[-1] if operands else None
    imm16 = (operands[0] | (operands[1] << 8)) if len(operands) >= 2 else None

    if x == 0:
        if z == 0:
            if y == 1:                                  # EX AF,AF'
                m.swap(("a",) + FLAGS)
            elif y == 2:                                # DJNZ (not taken: B is now 0)
                if imm8 == 0:
                    # (To the next instruction anyway)
                    state["b"] = None if state["b"] is None else (state["b"] - 1) & 0xff
                else:
                    state["b"] = 0
            elif y == 3:                                # JR
                state.block_end = True
            elif y >= 4 and imm8 != 0:                  # JR cc (not taken)
                m.condition(y - 4, False)
        elif z == 1:
            if q == 0:                                  # LD rp,nn
                m.set16(p, imm16)
            else:                                       # ADD HL,rp
                m.add16(2, m.get16(p))
        elif z == 2:
            if q == 1:
                if p == 2:                              # LD HL,(nn)
                    m.set16(2, None)
                else:                                   # LD A,(BC), (DE) or (nn)
                    state["a"] = None
        elif z == 3:                                    # INC rp, DEC rp
            v = m.get16(p)
            m.set16(p, None if v is None else v + (1 if q == 0 else -1))
        elif z in (4, 5):                               # INC r, DEC r
            if y == 6:
                m.inc_dec(None, z == 5)
            else:
                m.set8(y, m.inc_dec(m.get8(y), z == 5))
        elif z == 6:                                    # LD r,n
            m.set8(y, imm8)
        elif y < 4:                                     # RLCA, RRCA, RLA, RRA
            flags = {k: state[k] for k in ("s", "z", "pv")}
            state["a"] = m.rotate(y, state["a"])
            m.set_flags(**flags)
        elif y == 4:
            m.daa()
        elif y == 5:                                    # CPL
            state["a"] = None if state["a"] is None else state["a"] ^ 0xff
            m.set_flags(hc=True, n=True)
        elif y == 6:                                    # SCF
            m.set_flags(cy=True, hc=False, n=False)
        else:                                           # CCF
            cy = state["cy"]
            m.set_flags(hc=cy, cy=None if cy is None else not cy, n=False)

    elif x == 1:
        if y == 6 and z == 6:                           # HALT
            pass
        elif y == 6:                                    # LD (HL),r
            pass
        elif z == 6:                                    # LD r,(HL): (H and L stay H and L)
            m.set8(y, None, halves=False)
        else:                                           # LD r,r'
            m.set8(y, m.get8(z))

    elif x == 2:                                        # ADD ... CP
        if z == 6:
            m.alu(y, None)
        else:
            m.alu(y, m.get8(z), value_is_a=z == 7)

    elif z == 0:                                        # RET cc (not taken)
        m.condition(y, False)
    elif z == 1:
        if q == 0:                                      # POP rp
            names = m.pair_names(p, af=True)
            if p == 3:
                state["a"] = None
                m.set_flags(**dict.fromkeys(FLAGS))
            else:
                m.forget_pair(names)
            state["sp"] = None if state["sp"] is None else (state["sp"] + 2) & 0xffff
        elif p == 0:                                    # RET
            state.block_end = True
        elif p == 1:                                    # EXX
            m.swap(("b", "c", "d", "e", "h", "l"))
        elif p == 2:                                    # JP (HL)
            state.block_end = True
        else:                                           # LD SP,HL
            state["sp"] = m.get16(2)
    elif z == 2:                                        # JP cc,nn (not taken)
        if next_addr is not None and imm16 != next_addr:
            m.condition(y, False)
    elif z == 3:
        if y == 0:                                      # JP nn
            state.block_end = True
        elif y == 3:                                    # IN A,(n)
            state["a"] = None
        elif y == 4:                                    # EX (SP),HL
            m.set16(2, None)
        elif y == 5:                                    # EX DE,HL (never IX or IY)
            for a, b in (("d", "h"), ("e", "l")):
                state[a], state[b] = state[b], state[a]
        # (OUT (n),A, DI, EI change nothing tracked)
    elif z == 4 or (z == 5 and q == 1) or z == 7:
        # CALL cc,nn, CALL nn, RST: the subroutine could change anything
        state.clear()
    elif z == 5:                                        # PUSH rp
        state["sp"] = None if state["sp"] is None else (state["sp"] - 2) & 0xffff
    else:                                               # ADD A,n ... CP n
        m.alu(y, imm8)


def _cb(m, op, memory):
    """CB op (on (HL) if 'memory', in which case the value isn't known), or
    DD CB d op, FD CB d op."""
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    value = None if memory else m.get8(z)
    if x == 0:
        result = m.rotate(y, value)
        if not memory:
            m.set8(z, result)
    elif x == 1:
        m.bit(y, value)
    elif not memory:                                    # RES, SET
        mask = 1 << y
        m.set8(z, None if value is None else (value & ~mask if x == 2 else value | mask))


def _ed(m, op):
    """ED op."""
    state = m.state
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    p, q = y >> 1, y & 1
    if x == 1:
        if z == 0:                                      # IN r,(C), IN F,(C)
            if y != 6:
                state[R[y]] = None
            m.set_flags(s=None, z=None, pv=None, hc=False, n=False)
        elif z == 2:                                    # SBC HL,rp, ADC HL,rp
            m.add16(2, m.get16(p), carry=True, subtract=q == 0)
        elif z == 3 and q == 1:                         # LD rp,(nn)
            m.set16(p, None)
        elif z == 4:                                    # NEG
            a = state["a"]
            state["a"] = 0
            m.alu(2, a)
        elif z == 5:                                    # RETN, RETI
            state.block_end = True
        elif z == 7:
            if y == 0:                                  # LD I,A
                state["i"] = state["a"]
            elif y == 2:                                # LD A,I (P/V is IFF2)
                state["a"] = state["i"]
                m.set_szp(state["i"], parity=False)
                m.set_flags(hc=False, n=False, pv=None)
            elif y == 3:                                # LD A,R
                state["a"] = None
                m.set_flags(s=None, z=None, hc=False, n=False, pv=None)
            elif y in (4, 5):                           # RRD, RLD
                state["a"] = None
                m.set_flags(s=None, z=None, pv=None, hc=False, n=False)
        # (OUT (C),r, LD (nn),rp, IM n, LD R,A change nothing tracked)
    elif x == 2 and z <= 3 and y >= 4:
        repeat = y >= 6
        step = 1 if y in (4, 6) else -1
        bc, hl, de = m.get16(0), m.get16(2), m.get16(1)
        if z == 0:                                      # LDI, LDD, LDIR, LDDR
            if repeat:
                # (Finished: BC is 0, and HL and DE have moved by what it was)
                count = None if bc is None else (bc or 0x10000)
                m.set16(0, 0)
                m.set16(2, None if hl is None or count is None else hl + step * count)
                m.set16(1, None if de is None or count is None else de + step * count)
                m.set_flags(pv=False)
            else:
                m.set16(0, None if bc is None else bc - 1)
                m.set16(2, None if hl is None else hl + step)
                m.set16(1, None if de is None else de + step)
                m.set_flags(pv=None if bc is None else bc != 1)
            m.set_flags(hc=False, n=False)
        elif z == 1:                                    # CPI, CPD, CPIR, CPDR
            if repeat:
                # (Finished: when BC reached 0 or a byte matched)
                m.set16(0, None)
                m.set16(2, None)
                m.set_flags(pv=None)
            else:
                m.set16(0, None if bc is None else bc - 1)
                m.set16(2, None if hl is None else hl + step)
                m.set_flags(pv=None if bc is None else bc != 1)
            m.set_flags(s=None, z=None, hc=None, n=True)
        else:                                           # INI, OUTI, IND, OUTD and repeating
            b = state["b"]
            if repeat:
                count = None if b is None else (b or 0x100)
                state["b"] = 0
                m.set16(2, None if hl is None or count is None else hl + step * count)
                m.set_flags(z=True, s=False)
            else:
                state["b"] = None if b is None else (b - 1) & 0xff
                m.set16(2, None if hl is None else hl + step)
                m.set_szp(state["b"], parity=False)
            m.set_flags(hc=None, pv=None, n=None, cy=None)
    # (The other ED opcodes do nothing)
