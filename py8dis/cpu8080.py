import collections

import config
import expression
import classification
import config
import disassembly
import mainformatter
import output
import memorymanager
import movemanager
import session
import cpu
import trace
import utils
from memorymanager import BinaryAddr, RuntimeAddr
from binaryaddrtype import BinaryAddrType


OPCODE_RET = 0xc9

# The number of clock cycles (states) each opcode takes, from Intel's 8080
# documentation. (Checked against two emulators: superzazu/8080 and
# begoon/i8080-core.)
CYCLES = [
#   0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    4, 10,  7,  5,  5,  5,  7,  4,  4, 10,  7,  5,  5,  5,  7,  4,   # 0
    4, 10,  7,  5,  5,  5,  7,  4,  4, 10,  7,  5,  5,  5,  7,  4,   # 1
    4, 10, 16,  5,  5,  5,  7,  4,  4, 10, 16,  5,  5,  5,  7,  4,   # 2
    4, 10, 13,  5, 10, 10, 10,  4,  4, 10, 13,  5,  5,  5,  7,  4,   # 3
    5,  5,  5,  5,  5,  5,  7,  5,  5,  5,  5,  5,  5,  5,  7,  5,   # 4
    5,  5,  5,  5,  5,  5,  7,  5,  5,  5,  5,  5,  5,  5,  7,  5,   # 5
    5,  5,  5,  5,  5,  5,  7,  5,  5,  5,  5,  5,  5,  5,  7,  5,   # 6
    7,  7,  7,  7,  7,  7,  7,  7,  5,  5,  5,  5,  5,  5,  7,  5,   # 7
    4,  4,  4,  4,  4,  4,  7,  4,  4,  4,  4,  4,  4,  4,  7,  4,   # 8
    4,  4,  4,  4,  4,  4,  7,  4,  4,  4,  4,  4,  4,  4,  7,  4,   # 9
    4,  4,  4,  4,  4,  4,  7,  4,  4,  4,  4,  4,  4,  4,  7,  4,   # A
    4,  4,  4,  4,  4,  4,  7,  4,  4,  4,  4,  4,  4,  4,  7,  4,   # B
    5, 10, 10, 10, 11, 11,  7, 11,  5, 10, 10, 10, 11, 17,  7, 11,   # C
    5, 10, 10, 10, 11, 11,  7, 11,  5, 10, 10, 10, 11, 17,  7, 11,   # D
    5, 10, 10, 18, 11, 11,  7, 11,  5,  5, 10,  4, 11, 17,  7, 11,   # E
    5, 10, 10,  4, 11, 11,  7, 11,  5,  5, 10,  4, 11, 17,  7, 11,   # F
]

# A conditional return or call takes 6 more cycles if it's taken, e.g. RNZ
# takes 5, or 11 if it returns
CONDITIONAL_RETURNS = { 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8 }
CONDITIONAL_CALLS   = { 0xc4, 0xcc, 0xd4, 0xdc, 0xe4, 0xec, 0xf4, 0xfc }

def cycles_description(opcode):
    """The cycles an opcode takes, as text, e.g. "7", or "5/11" for a
    conditional return (not taken, or taken)."""
    if opcode in CONDITIONAL_RETURNS or opcode in CONDITIONAL_CALLS:
        return "%d/%d" % (CYCLES[opcode], CYCLES[opcode] + 6)
    return str(CYCLES[opcode])

# Tracking what's known about the registers and flags (see Cpu8080.CpuState)

# The registers in the order the opcodes number them ('m' is the memory at HL)
REGISTER_ORDER = ("b", "c", "d", "e", "h", "l", "m", "a")

# The register pairs, as the opcodes number them (for PUSH and POP, 3 is PSW)
REGISTER_PAIRS = (("b", "c"), ("d", "e"), ("h", "l"), "sp")

def _parity(value):
    """True if an 8 bit value has an even number of bits set."""
    return bin(value).count("1") % 2 == 0

def _set_szp(state, value):
    state["s"] = value >= 0x80
    state["z"] = value == 0
    state["p"] = _parity(value)

def _forget_szp(state):
    state["s"] = state["z"] = state["p"] = None

def _get_pair(state, pair):
    if pair == "sp":
        return state["sp"]
    hi, lo = state[pair[0]], state[pair[1]]
    return None if hi is None or lo is None else (hi << 8) | lo

def _set_pair(state, pair, value):
    if pair == "sp":
        state["sp"] = None if value is None else value & 0xffff
    elif value is None:
        state[pair[0]] = state[pair[1]] = None
    else:
        state[pair[0]] = (value >> 8) & 0xff
        state[pair[1]] = value & 0xff

def _alu(state, op, value):
    """ADD, ADC, SUB, SBB, ANA, XRA, ORA or CMP (op 0 to 7) of A with
    'value' (None if not known)."""
    a = state["a"]
    cy = state["cy"]
    if op in (0, 1, 2, 3, 7):
        # Addition, or subtraction (as A + NOT value + 1)
        subtract = op in (2, 3, 7)
        carry_in = 0 if op in (0, 7, 2) else cy
        if op in (2, 7):
            carry_in = 1
        elif op == 3:
            carry_in = None if cy is None else (0 if cy else 1)
        if a is None or value is None or carry_in is None:
            if op != 7:
                state["a"] = None
            _forget_szp(state)
            state["cy"] = state["ac"] = None
            return
        b = (value ^ 0xff) if subtract else value
        total = a + b + carry_in
        result = total & 0xff
        state["ac"] = bool((a ^ b ^ total) & 0x10)
        state["cy"] = (total > 0xff) != subtract
        _set_szp(state, result)
        if op != 7:
            state["a"] = result
        return

    # ANA, XRA, ORA: the carry is cleared
    state["cy"] = False
    if op == 4:
        state["ac"] = None if a is None or value is None else bool((a | value) & 0x08)
    else:
        state["ac"] = False
    if a is None or value is None:
        # (Except that A XRA A is always 0)
        if op == 5 and value == "a":
            a = value = 0
        else:
            state["a"] = None
            _forget_szp(state)
            return
    result = a & value if op == 4 else a ^ value if op == 5 else a | value
    state["a"] = result
    _set_szp(state, result)

def update_state(state, opcode, operands):
    """Update what's known about the CPU (a Cpu8080.CpuState) for the
    instruction with the given opcode and operand bytes, so that it's what's
    known once the instruction has run (assuming a conditional jump, call or
    return isn't taken: if it is, the code doesn't continue to the next
    instruction)."""

    def reg(index):
        """The value of a register (by its number in the opcode), or None."""
        name = REGISTER_ORDER[index]
        return None if name == "m" else state[name]

    def set_reg(index, value):
        name = REGISTER_ORDER[index]
        if name != "m":
            state[name] = value

    imm8 = operands[0] if len(operands) >= 1 else None
    imm16 = (operands[0] | (operands[1] << 8)) if len(operands) == 2 else None
    pair = REGISTER_PAIRS[(opcode >> 4) & 3]

    if 0x40 <= opcode <= 0x7f:
        if opcode != 0x76:                              # MOV (0x76 is HLT)
            set_reg((opcode >> 3) & 7, reg(opcode & 7))
    elif 0x80 <= opcode <= 0xbf:                        # ADD ... CMP with a register
        src = opcode & 7
        _alu(state, (opcode >> 3) & 7, "a" if (src == 7 and state["a"] is None) else reg(src))
    elif (opcode & 0xc7) == 0xc6:                       # ADI ... CPI
        _alu(state, (opcode >> 3) & 7, imm8)
    elif (opcode & 0xc7) == 0x06:                       # MVI
        set_reg((opcode >> 3) & 7, imm8)
    elif (opcode & 0xc6) == 0x04:                       # INR, DCR
        index = (opcode >> 3) & 7
        v = reg(index)
        if v is None:
            set_reg(index, None)
            _forget_szp(state)
            state["ac"] = None
        else:
            result = (v + (1 if (opcode & 1) == 0 else -1)) & 0xff
            set_reg(index, result)
            _set_szp(state, result)
            state["ac"] = (result & 0xf) == 0 if (opcode & 1) == 0 else (result & 0xf) != 0xf
    elif (opcode & 0xcf) == 0x01:                       # LXI
        _set_pair(state, pair, imm16)
    elif (opcode & 0xc7) == 0x03:                       # INX, DCX
        v = _get_pair(state, pair)
        _set_pair(state, pair, None if v is None else v + (1 if (opcode & 8) == 0 else -1))
    elif (opcode & 0xcf) == 0x09:                       # DAD
        hl, v = _get_pair(state, ("h", "l")), _get_pair(state, pair)
        if hl is None or v is None:
            _set_pair(state, ("h", "l"), None)
            state["cy"] = None
        else:
            _set_pair(state, ("h", "l"), hl + v)
            state["cy"] = hl + v > 0xffff
    elif opcode in (0x0a, 0x1a, 0x3a, 0xdb):            # LDAX, LDA, IN
        state["a"] = None
    elif opcode == 0x2a:                                # LHLD
        _set_pair(state, ("h", "l"), None)
    elif opcode in (0x07, 0x0f, 0x17, 0x1f):            # RLC, RRC, RAL, RAR
        a, cy = state["a"], state["cy"]
        if opcode == 0x07:
            state["cy"] = None if a is None else a >= 0x80
            state["a"] = None if a is None else ((a << 1) | (a >> 7)) & 0xff
        elif opcode == 0x0f:
            state["cy"] = None if a is None else bool(a & 1)
            state["a"] = None if a is None else ((a >> 1) | ((a & 1) << 7))
        elif opcode == 0x17:
            state["cy"] = None if a is None else a >= 0x80
            state["a"] = None if a is None or cy is None else ((a << 1) | int(cy)) & 0xff
        else:
            state["cy"] = None if a is None else bool(a & 1)
            state["a"] = None if a is None or cy is None else (a >> 1) | (int(cy) << 7)
    elif opcode == 0x27:                                # DAA
        a, cy, ac = state["a"], state["cy"], state["ac"]
        if a is None or cy is None or ac is None:
            state["a"] = state["cy"] = state["ac"] = None
            _forget_szp(state)
        else:
            correction = 0
            lsb, msb = a & 0x0f, a >> 4
            if ac or lsb > 9:
                correction += 0x06
            if cy or msb > 9 or (msb >= 9 and lsb > 9):
                correction += 0x60
                cy = True
            _alu(state, 0, correction)
            state["cy"] = cy
    elif opcode == 0x2f:                                # CMA
        state["a"] = None if state["a"] is None else state["a"] ^ 0xff
    elif opcode == 0x37:                                # STC
        state["cy"] = True
    elif opcode == 0x3f:                                # CMC
        state["cy"] = None if state["cy"] is None else not state["cy"]
    elif opcode == 0xeb:                                # XCHG
        state["d"], state["e"], state["h"], state["l"] = state["h"], state["l"], state["d"], state["e"]
    elif opcode == 0xe3:                                # XTHL
        _set_pair(state, ("h", "l"), None)
    elif opcode == 0xf9:                                # SPHL
        state["sp"] = _get_pair(state, ("h", "l"))
    elif (opcode & 0xcf) == 0xc5:                       # PUSH
        _set_pair(state, "sp", None if state["sp"] is None else state["sp"] - 2)
    elif (opcode & 0xcf) == 0xc1:                       # POP
        if opcode == 0xf1:
            state["a"] = None
            for name in Cpu8080.CpuState.FLAGS:
                state[name] = None
        else:
            _set_pair(state, pair, None)
        _set_pair(state, "sp", None if state["sp"] is None else state["sp"] + 2)
    elif (opcode & 0xc7) in (0xc0, 0xc2):               # Rcc, Jcc (when not taken)
        pass
    elif opcode in (0xc3, 0xcb, 0xe9):                  # JMP, PCHL
        state.block_end = True
    elif opcode in (0xc9, 0xd9):                        # RET
        _set_pair(state, "sp", None if state["sp"] is None else state["sp"] + 2)
        state.block_end = True
    elif (opcode & 0xc7) == 0xc4 or opcode in (0xcd, 0xdd, 0xed, 0xfd) or (opcode & 0xc7) == 0xc7:
        # Ccc, CALL, RST: the subroutine called could change anything
        state.clear()
        if (opcode & 0xc7) == 0xc7:
            state.block_end = True              # (RST isn't traced past)
    # Otherwise the instruction changes nothing that's tracked: NOP, STAX,
    # SHLD, STA, MOV M,r, MVI M, OUT, EI, DI, HLT

class Cpu8080(cpu.Cpu):
    """Class representing an 8080 CPU"""

    def __init__(self):
        super().__init__()

        #TODO: self.code_analysis_fns.append(subroutine_argument_finder)

        # For labelling ret instructions numerically
        self.return_index = 0
        self.return_array = {}

        # indent_level_dict has binary addresses as the keys, and indent amounts as the values.

        # TODO: indent_level_dict is a bit of a hack (after all, arguably
        # byte/word directives etc should have it too) and should
        # probably be handled at a higher level by the code controlling
        # emission of text disassembly output
        self.indent_level_dict = collections.defaultdict(int)

        self.opcodes = {
            0x00: self.OpcodeImplied("NOP"),
            0x01: self.OpcodeImmediate16("LXI BC,"),
            0x02: self.OpcodeImplied("STAX B"),
            0x03: self.OpcodeImplied("INX B"),
            0x04: self.OpcodeImplied("INR B"),
            0x05: self.OpcodeImplied("DCR B"),
            0x06: self.OpcodeImmediate("MVI B,"),
            0x07: self.OpcodeImplied("RLC"),
            0x08: self.OpcodeUndocumentedImplied("NOP"),
            0x09: self.OpcodeImplied("DAD B"),
            0x0a: self.OpcodeImplied("LDAX B"),
            0x0b: self.OpcodeImplied("DCX B"),
            0x0c: self.OpcodeImplied("INR C"),
            0x0d: self.OpcodeImplied("DCR C"),
            0x0e: self.OpcodeImmediate("MVI C,"),
            0x0f: self.OpcodeImplied("RRC"),

            0x10: self.OpcodeUndocumentedImplied("NOP"),
            0x11: self.OpcodeImmediate16("LXI DE,"),
            0x12: self.OpcodeImplied("STAX D"),
            0x13: self.OpcodeImplied("INX D"),
            0x14: self.OpcodeImplied("INR D"),
            0x15: self.OpcodeImplied("DCR D"),
            0x16: self.OpcodeImmediate("MVI D,"),
            0x17: self.OpcodeImplied("RAL"),
            0x18: self.OpcodeUndocumentedImplied("NOP"),
            0x19: self.OpcodeImplied("DAD D"),
            0x1a: self.OpcodeImplied("LDAX D"),
            0x1b: self.OpcodeImplied("DCX D"),
            0x1c: self.OpcodeImplied("INR E"),
            0x1d: self.OpcodeImplied("DCR E"),
            0x1e: self.OpcodeImmediate("MVI E,"),
            0x1f: self.OpcodeImplied("RAR"),

            0x20: self.OpcodeUndocumentedImplied("NOP"),
            0x21: self.OpcodeImmediate16("LXI HL,"),
            0x22: self.OpcodeAddr16("SHLD"),
            0x23: self.OpcodeImplied("INX H"),
            0x24: self.OpcodeImplied("INR H"),
            0x25: self.OpcodeImplied("DCR H"),
            0x26: self.OpcodeImmediate("MVI H,"),
            0x27: self.OpcodeImplied("DAA"),
            0x28: self.OpcodeUndocumentedImplied("NOP"),
            0x29: self.OpcodeImplied("DAD H"),
            0x2a: self.OpcodeAddr16("LHLD"),
            0x2b: self.OpcodeImplied("DCX H"),
            0x2c: self.OpcodeImplied("INR L"),
            0x2d: self.OpcodeImplied("DCR L"),
            0x2e: self.OpcodeImmediate("MVI L,"),
            0x2f: self.OpcodeImplied("CMA"),

            0x30: self.OpcodeUndocumentedImplied("NOP"),
            0x31: self.OpcodeImmediate16("LXI SP,"),
            0x32: self.OpcodeAddr16("STA"),
            0x33: self.OpcodeImplied("INX SP"),
            0x34: self.OpcodeImplied("INR M"),
            0x35: self.OpcodeImplied("DCR M"),
            0x36: self.OpcodeImmediate("MVI M,"),
            0x37: self.OpcodeImplied("STC"),
            0x38: self.OpcodeUndocumentedImplied("NOP"),
            0x39: self.OpcodeImplied("DAD SP"),
            0x3a: self.OpcodeAddr16("LDA"),
            0x3b: self.OpcodeImplied("DCX SP"),
            0x3c: self.OpcodeImplied("INR A"),
            0x3d: self.OpcodeImplied("DCR A"),
            0x3e: self.OpcodeImmediate("MVI A,"),
            0x3f: self.OpcodeImplied("CMC"),

            0x40: self.OpcodeImplied("MOV B, B"),
            0x41: self.OpcodeImplied("MOV B, C"),
            0x42: self.OpcodeImplied("MOV B, D"),
            0x43: self.OpcodeImplied("MOV B, E"),
            0x44: self.OpcodeImplied("MOV B, H"),
            0x45: self.OpcodeImplied("MOV B, L"),
            0x46: self.OpcodeImplied("MOV B, M"),
            0x47: self.OpcodeImplied("MOV B, A"),
            0x48: self.OpcodeImplied("MOV C, B"),
            0x49: self.OpcodeImplied("MOV C, C"),
            0x4a: self.OpcodeImplied("MOV C, D"),
            0x4b: self.OpcodeImplied("MOV C, E"),
            0x4c: self.OpcodeImplied("MOV C, H"),
            0x4d: self.OpcodeImplied("MOV C, L"),
            0x4e: self.OpcodeImplied("MOV C, M"),
            0x4f: self.OpcodeImplied("MOV C, A"),

            0x50: self.OpcodeImplied("MOV D, B"),
            0x51: self.OpcodeImplied("MOV D, C"),
            0x52: self.OpcodeImplied("MOV D, D"),
            0x53: self.OpcodeImplied("MOV D, E"),
            0x54: self.OpcodeImplied("MOV D, H"),
            0x55: self.OpcodeImplied("MOV D, L"),
            0x56: self.OpcodeImplied("MOV D, M"),
            0x57: self.OpcodeImplied("MOV D, A"),
            0x58: self.OpcodeImplied("MOV E, B"),
            0x59: self.OpcodeImplied("MOV E, C"),
            0x5a: self.OpcodeImplied("MOV E, D"),
            0x5b: self.OpcodeImplied("MOV E, E"),
            0x5c: self.OpcodeImplied("MOV E, H"),
            0x5d: self.OpcodeImplied("MOV E, L"),
            0x5e: self.OpcodeImplied("MOV E, M"),
            0x5f: self.OpcodeImplied("MOV E, A"),

            0x60: self.OpcodeImplied("MOV H, B"),
            0x61: self.OpcodeImplied("MOV H, C"),
            0x62: self.OpcodeImplied("MOV H, D"),
            0x63: self.OpcodeImplied("MOV H, E"),
            0x64: self.OpcodeImplied("MOV H, H"),
            0x65: self.OpcodeImplied("MOV H, L"),
            0x66: self.OpcodeImplied("MOV H, M"),
            0x67: self.OpcodeImplied("MOV H, A"),
            0x68: self.OpcodeImplied("MOV L, B"),
            0x69: self.OpcodeImplied("MOV L, C"),
            0x6a: self.OpcodeImplied("MOV L, D"),
            0x6b: self.OpcodeImplied("MOV L, E"),
            0x6c: self.OpcodeImplied("MOV L, H"),
            0x6d: self.OpcodeImplied("MOV L, L"),
            0x6e: self.OpcodeImplied("MOV L, M"),
            0x6f: self.OpcodeImplied("MOV L, A"),

            0x70: self.OpcodeImplied("MOV M, B"),
            0x71: self.OpcodeImplied("MOV M, C"),
            0x72: self.OpcodeImplied("MOV M, D"),
            0x73: self.OpcodeImplied("MOV M, E"),
            0x74: self.OpcodeImplied("MOV M, H"),
            0x75: self.OpcodeImplied("MOV M, L"),
            0x76: self.OpcodeImplied("HLT"),
            0x77: self.OpcodeImplied("MOV M, A"),
            0x78: self.OpcodeImplied("MOV A, B"),
            0x79: self.OpcodeImplied("MOV A, C"),
            0x7a: self.OpcodeImplied("MOV A, D"),
            0x7b: self.OpcodeImplied("MOV A, E"),
            0x7c: self.OpcodeImplied("MOV A, H"),
            0x7d: self.OpcodeImplied("MOV A, L"),
            0x7e: self.OpcodeImplied("MOV A, M"),
            0x7f: self.OpcodeImplied("MOV A, A"),

            0x80: self.OpcodeImplied("ADD B"),
            0x81: self.OpcodeImplied("ADD C"),
            0x82: self.OpcodeImplied("ADD D"),
            0x83: self.OpcodeImplied("ADD E"),
            0x84: self.OpcodeImplied("ADD H"),
            0x85: self.OpcodeImplied("ADD L"),
            0x86: self.OpcodeImplied("ADD M"),
            0x87: self.OpcodeImplied("ADD A"),
            0x88: self.OpcodeImplied("ADC B"),
            0x89: self.OpcodeImplied("ADC C"),
            0x8a: self.OpcodeImplied("ADC D"),
            0x8b: self.OpcodeImplied("ADC E"),
            0x8c: self.OpcodeImplied("ADC H"),
            0x8d: self.OpcodeImplied("ADC L"),
            0x8e: self.OpcodeImplied("ADC M"),
            0x8f: self.OpcodeImplied("ADC A"),

            0x90: self.OpcodeImplied("SUB B"),
            0x91: self.OpcodeImplied("SUB C"),
            0x92: self.OpcodeImplied("SUB D"),
            0x93: self.OpcodeImplied("SUB E"),
            0x94: self.OpcodeImplied("SUB H"),
            0x95: self.OpcodeImplied("SUB L"),
            0x96: self.OpcodeImplied("SUB M"),
            0x97: self.OpcodeImplied("SUB A"),
            0x98: self.OpcodeImplied("SBB B"),
            0x99: self.OpcodeImplied("SBB C"),
            0x9a: self.OpcodeImplied("SBB D"),
            0x9b: self.OpcodeImplied("SBB E"),
            0x9c: self.OpcodeImplied("SBB H"),
            0x9d: self.OpcodeImplied("SBB L"),
            0x9e: self.OpcodeImplied("SBB M"),
            0x9f: self.OpcodeImplied("SBB A"),

            0xa0: self.OpcodeImplied("ANA B"),
            0xa1: self.OpcodeImplied("ANA C"),
            0xa2: self.OpcodeImplied("ANA D"),
            0xa3: self.OpcodeImplied("ANA E"),
            0xa4: self.OpcodeImplied("ANA H"),
            0xa5: self.OpcodeImplied("ANA L"),
            0xa6: self.OpcodeImplied("ANA M"),
            0xa7: self.OpcodeImplied("ANA A"),
            0xa8: self.OpcodeImplied("XRA B"),
            0xa9: self.OpcodeImplied("XRA C"),
            0xaa: self.OpcodeImplied("XRA D"),
            0xab: self.OpcodeImplied("XRA E"),
            0xac: self.OpcodeImplied("XRA H"),
            0xad: self.OpcodeImplied("XRA L"),
            0xae: self.OpcodeImplied("XRA M"),
            0xaf: self.OpcodeImplied("XRA A"),

            0xb0: self.OpcodeImplied("ORA B"),
            0xb1: self.OpcodeImplied("ORA C"),
            0xb2: self.OpcodeImplied("ORA D"),
            0xb3: self.OpcodeImplied("ORA E"),
            0xb4: self.OpcodeImplied("ORA H"),
            0xb5: self.OpcodeImplied("ORA L"),
            0xb6: self.OpcodeImplied("ORA M"),
            0xb7: self.OpcodeImplied("ORA A"),
            0xb8: self.OpcodeImplied("CMP B"),
            0xb9: self.OpcodeImplied("CMP C"),
            0xba: self.OpcodeImplied("CMP D"),
            0xbb: self.OpcodeImplied("CMP E"),
            0xbc: self.OpcodeImplied("CMP H"),
            0xbd: self.OpcodeImplied("CMP L"),
            0xbe: self.OpcodeImplied("CMP M"),
            0xbf: self.OpcodeImplied("CMP A"),

            0xc0: self.OpcodeImplied("RNZ"),
            0xc1: self.OpcodeImplied("POP B"),
            0xc2: self.OpcodeConditionalBranch("JNZ"),
            0xc3: self.OpcodeJmp("JMP"),
            0xc4: self.OpcodeCall("CNZ"),
            0xc5: self.OpcodeImplied("PUSH B"),
            0xc6: self.OpcodeImmediate("ADI"),
            0xc7: self.OpcodeReset("RST 0"),
            0xc8: self.OpcodeImplied("RZ"),
            0xc9: self.OpcodeReturn("RET"),
            0xca: self.OpcodeConditionalBranch("JZ"),
            0xcb: self.OpcodeUndocumentedJmp("JMP"),
            0xcc: self.OpcodeCall("CZ"),
            0xcd: self.OpcodeCall("CALL"),
            0xce: self.OpcodeImmediate("ACI"),
            0xcf: self.OpcodeReset("RST 1"),

            0xd0: self.OpcodeImplied("RNC"),
            0xd1: self.OpcodeImplied("POP D"),
            0xd2: self.OpcodeConditionalBranch("JNC"),
            0xd3: self.OpcodeImmediate("OUT"),
            0xd4: self.OpcodeCall("CNC"),
            0xd5: self.OpcodeImplied("PUSH D"),
            0xd6: self.OpcodeImmediate("SUI"),
            0xd7: self.OpcodeReset("RST 2"),
            0xd8: self.OpcodeImplied("RC"),
            0xd9: self.OpcodeUndocumentedReturn("RET"),
            0xda: self.OpcodeConditionalBranch("JC"),
            0xdb: self.OpcodeImmediate("IN"),
            0xdc: self.OpcodeCall("CC"),
            0xdd: self.OpcodeUndocumentedCall("CALL"),
            0xde: self.OpcodeImmediate("SBI"),
            0xdf: self.OpcodeReset("RST 3"),

            0xe0: self.OpcodeImplied("RPO"),
            0xe1: self.OpcodeImplied("POP H"),
            0xe2: self.OpcodeConditionalBranch("JPO"),
            0xe3: self.OpcodeImplied("XTHL"),
            0xe4: self.OpcodeCall("CPO"),
            0xe5: self.OpcodeImplied("PUSH H"),
            0xe6: self.OpcodeImmediate("ANI"),
            0xe7: self.OpcodeReset("RST 4"),
            0xe8: self.OpcodeImplied("RPE"),
            0xe9: self.OpcodeJmpInd("PCHL"),
            0xea: self.OpcodeConditionalBranch("JPE"),
            0xeb: self.OpcodeImplied("XCHG"),
            0xec: self.OpcodeCall("CPE"),
            0xed: self.OpcodeUndocumentedCall("CALL"),
            0xee: self.OpcodeImmediate("XRI"),
            0xef: self.OpcodeReset("RST 5"),

            0xf0: self.OpcodeImplied("RP"),
            0xf1: self.OpcodeImplied("POP PSW"),
            0xf2: self.OpcodeConditionalBranch("JP P,"),
            0xf3: self.OpcodeImplied("DI"),
            0xf4: self.OpcodeCall("CALL P,"),
            0xf5: self.OpcodeImplied("PUSH PSW"),
            0xf6: self.OpcodeImmediate("ORI"),
            0xf7: self.OpcodeReset("RST 6"),
            0xf8: self.OpcodeImplied("RM"),
            0xf9: self.OpcodeImplied("SPHL"),
            0xfa: self.OpcodeConditionalBranch("JM"),
            0xfb: self.OpcodeImplied("EI"),
            0xfc: self.OpcodeCall("CM"),
            0xfd: self.OpcodeUndocumentedCall("CALL"),
            0xfe: self.OpcodeImmediate("CPI"),
            0xff: self.OpcodeReset("RST 7"),
        }

        # The cycles each opcode takes
        assert len(self.opcodes) == 256
        for opcode, op in self.opcodes.items():
            op.cycles = cycles_description(opcode)

    def hook_subroutine(self, runtime_addr, name, hook):
        runtime_addr = RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        self.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, name, explicit=True)
        self.subroutine_hooks[runtime_addr] = hook

    def get_target_binary_addr_preferring_given_move_id(self, runtime_addr, specific_move_id):
        """Given an instruction's operand address (a runtime address), find it's most likely
        binary address, for the current set of active move ids.
        """
        # Try the specific move id first...
        binary_addr, _ = movemanager.r2b(runtime_addr, specific_move_id)
        if binary_addr is None:
            # If that doesn't work, try without a specific move id...
            binary_addr, _ = movemanager.r2b(runtime_addr)
            if binary_addr is None:
                assert False
                return []
        return [binary_addr]

    class Opcode:
        def __init__(self, mnemonic, operand_length, suffix = None, update=None):
            self.mnemonic = mnemonic
            self.suffix = suffix if suffix is not None else ""
            self.prefix = "(" if ")" in self.suffix else ""
            self.update = update
            self.operand_length = operand_length
            self.cycles = "???"         # (Set by Cpu8080.__init__())

        def length(self):
            return 1 + self.operand_length

        def is_code(self, binary_addr):
            return True

        def update_cpu_state(self, binary_addr, state):
            # Nothing is known after an instruction the code can't continue
            # from (e.g. JMP), or where code can come from elsewhere (at a
            # label)
            runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
            if state.block_end or (runtime_addr is not None and runtime_addr in session.current().labels.labels):
                state.clear()
            memory_binary = session.current().memory.binary
            operands = [memory_binary[binary_addr + 1 + i] for i in range(self.operand_length)]
            update_state(state, memory_binary[binary_addr], operands)

        def update_references(self, binary_loc):
            pass

        def is_block_end(self):
            return False

        def cycles_description(self, binary_addr):
            """The cycles the instruction takes, as shown with
            config.set_show_cycles(True), e.g. "7" or "5/11"."""
            return self.cycles

        def instruction(self, binary_addr):
            """The instruction (see output.Instruction)."""
            return output.Instruction(self.mnemonic)

        def address_operand(self, binary_addr):
            """The 16 bit address operand (following the opcode at binary_addr) as a string."""
            operand = classification.get_address16(binary_addr + 1)
            if self.prefix:
                # Already in brackets, e.g. an indirect address
                return operand
            return expression.in_context(operand, expression.OPERAND)

        def as_lines(self, binary_loc, annotations):
            """The output for the instruction at binary_loc, as a list of
            line objects (see output.py)."""
            binary_addr = binary_loc.binary_addr
            result = [self.instruction(binary_addr).placed(binary_loc, self.length(), session.current().cpu.indent_level_dict.get(binary_addr, 0),
                                                           self.cycles_description(binary_addr), annotations)]
            if self.is_block_end() and config.get_blank_line_at_block_end():
                result.append(output.Blank())
            return result


    class OpcodeImplied(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 0, update=update)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 1]


    class OpcodeImmediate(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 1, update=update)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 2]

        def instruction(self, binary_addr):
            memory_binary = session.current().memory.binary
            operand = expression.in_context(classification.get_constant8(binary_addr + 1), expression.OPERAND)
            char_literal = None
            if (binary_addr + 1) not in session.current().classifications.expressions and session.current().disassembly.format_hint.get(binary_addr + 1) is None:
                c = memory_binary[binary_addr + 1]
                if config.get_show_char_literals() and utils.isprint(c):
                    char_literal = "'%s'" % chr(c)
            return output.Instruction(self.mnemonic, operand, char_literal=char_literal)


    class OpcodeImmediate16(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 2, update=update)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 3]

        def instruction(self, binary_addr):
            memory_binary = session.current().memory.binary
            operand = expression.in_context(classification.get_constant16(binary_addr + 1), expression.OPERAND)
            char_literal = None
            if (binary_addr + 1) not in session.current().classifications.expressions and session.current().disassembly.format_hint.get(binary_addr + 1) is None:
                c = memory_binary[binary_addr + 1]
                if config.get_show_char_literals() and utils.isprint(c):
                    char_literal = "'%s'" % chr(c)
            return output.Instruction(self.mnemonic, operand, char_literal=char_literal)

    class OpcodeAddr16(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 2, update=update)

        def abs_operand(self, binary_addr):
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def instruction(self, binary_addr):
            return output.Instruction(self.mnemonic, self.address_operand(binary_addr), prefix=self.prefix, suffix=self.suffix)

        def update_references(self, binary_loc):
            session.current().labels.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 3]

    class OpcodeJmp(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 2, update=update)

        def _target(self, binary_addr):
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def abs_operand(self, binary_addr):
            return self._target(binary_addr)

        def instruction(self, binary_addr):
            return output.Instruction(self.mnemonic, self.address_operand(binary_addr), prefix=self.prefix, suffix=self.suffix)

        def update_references(self, binary_loc):
            session.current().labels.labels[self._target(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            return True

        def disassemble(self, binary_loc):
            # Get the destination location of the JMP
            target_runtime_addr = self._target(binary_loc.binary_addr)
            target_binary_addr, target_move_id = movemanager.r2b(target_runtime_addr)

            return [None, target_binary_addr]

    class OpcodeJmpInd(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 0, update=update)

        def is_block_end(self):
            return True

        def disassemble(self, binary_loc):
            return [None]


    class OpcodeConditionalBranch(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 2, update=update)

        def _target(self, binary_addr):
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def abs_operand(self, binary_addr):
            return self._target(binary_addr)

        def update_references(self, binary_loc):
            session.current().labels.labels[self._target(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 3] + session.current().cpu.get_target_binary_addr_preferring_given_move_id(self._target(binary_loc.binary_addr), binary_loc.move_id)

        def instruction(self, binary_addr):
            label = disassembly.get_label(self._target(binary_addr), binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
            return output.Instruction(self.mnemonic, label)

    class OpcodeCall(Opcode):
        def __init__(self, mnemonic, update=None):
            super().__init__(mnemonic, 2, update=update)

        def _target(self, binary_addr):
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def abs_operand(self, binary_addr):
            return self._target(binary_addr)

        def update_references(self, binary_loc):
            session.current().labels.labels[self._target(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            assert isinstance(binary_loc.binary_addr, BinaryAddr)

            # Get the destination location of the CALL
            target_runtime_addr = self._target(binary_loc.binary_addr)
            target_binary_addr, target_move_id = movemanager.r2b(target_runtime_addr)

            # A hook only gets to return the "straight line" address to continue
            # tracing from (if there is one; it can return None if it wishes). Some
            # subroutines (e.g. jsr is_yx_zero:equw target_if_true, target_if_false)
            # might have no "straight line" case and want to return some labelled
            # entry points. This is supported by having the hook simply return None
            # and call entry() itself for the labelled entry points.

            def simple_call_hook(target_runtime_addr, caller_runtime_addr):
                assert isinstance(target_runtime_addr, RuntimeAddr)
                assert isinstance(caller_runtime_addr, RuntimeAddr)

                return caller_runtime_addr + 3

            call_hook = session.current().cpu.subroutine_hooks.get(target_runtime_addr, simple_call_hook)
            caller_runtime_addr = movemanager.b2r(binary_loc.binary_addr)
            with session.current().moves.move_id_for_binary_addr[binary_loc.binary_addr]:
                return_runtime_addr = call_hook(target_runtime_addr, caller_runtime_addr)

            if return_runtime_addr is not None:
                return_runtime_addr = RuntimeAddr(return_runtime_addr)
                result = session.current().cpu.get_target_binary_addr_preferring_given_move_id(return_runtime_addr, binary_loc.move_id)
                if len(result) == 0:
                    # The return runtime address could not be unambiguously converted into a binary
                    # address. It's highly likely the 'CALL' is returning to the immediately following
                    # instruction, so if binary_addr+3 maps to the return runtime address, use that,
                    # otherwise give up and don't trace anything "after" the 'CALL'.
                    simple_return_binary_addr = binary_addr + 3
                    if return_runtime_addr == movemanager.b2r(simple_return_binary_addr):
                        result = [simple_return_binary_addr]
                    else:
                        result = [None]
            else:
                result = [None]
            result += [target_binary_addr]
            return result

        def instruction(self, binary_addr):
            return output.Instruction(self.mnemonic, self.address_operand(binary_addr), prefix=self.prefix, suffix=self.suffix)

    class OpcodeReturn(Opcode):
        def __init__(self, mnemonic):
            super().__init__(mnemonic, 0)

        def disassemble(self, binary_loc):
            return [None]

        def is_block_end(self):
            return True

    # The undocumented opcodes: &08, &10, &18, &20, &28, &30 and &38 run as
    # NOP, &CB as JMP, &D9 as RET, and &DD, &ED and &FD as CALL. They're
    # traced as what they run as, but output as data bytes (see
    # output.Instruction.UNDOCUMENTED), since assemblers don't accept them.

    class Undocumented:
        """Outputs an undocumented opcode as data bytes (the opcode, then
        the operand's low and high bytes, if any), with the instruction it
        runs as in a comment."""

        def instruction(self, binary_addr):
            instruction = super().instruction(binary_addr)
            instruction.form = output.Instruction.UNDOCUMENTED
            instruction.data_byte = expression.Num(session.current().memory.binary[binary_addr], "hex2")
            return instruction

    class OpcodeUndocumentedImplied(Undocumented, OpcodeImplied):
        pass

    class OpcodeUndocumentedJmp(Undocumented, OpcodeJmp):
        pass

    class OpcodeUndocumentedReturn(Undocumented, OpcodeReturn):
        pass

    class OpcodeUndocumentedCall(Undocumented, OpcodeCall):
        pass

    class OpcodeReset(Opcode):
        def __init__(self, mnemonic):
            super().__init__(mnemonic, 0)

        def disassemble(self, binary_loc):
            return [None]

        def is_block_end(self):
            return True

    class CpuState:
        """What's known for certain about the registers and flags (see
        update_state()): each register's value (A, B, C, D, E, H, L as 8 bit
        numbers, SP as a 16 bit number) and each flag's (S, Z, AC (the
        auxiliary or half carry), P and CY, as True or False), or None if
        it's not known."""

        REGISTERS = ("a", "b", "c", "d", "e", "h", "l", "sp")
        FLAGS     = ("s", "z", "ac", "p", "cy")

        def __init__(self):
            self.clear(pessimistic_only=False)

        def clear(self, *, pessimistic_only=False):
            """Forget everything. (There's only one state for the 8080, so
            'pessimistic_only' makes no difference.)"""
            self.values = dict.fromkeys(self.REGISTERS + self.FLAGS)

            # True after an instruction the following instruction can't be
            # reached from (e.g. JMP or RET), so that it starts with nothing
            # known
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
            'A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- sZ-pc': each register
            in hex ('--' if not known), then each flag (S, Z, AC, P, CY) as
            an upper case letter if set, lower case if clear, or '-' if not
            known."""
            def reg(name):
                v = self.values[name]
                if name == "sp":
                    return "----" if v is None else utils.plainhex4(v)
                return "--" if v is None else utils.plainhex2(v)
            def flag(name, letter):
                v = self.values[name]
                return "-" if v is None else (letter.upper() if v else letter)
            return " ".join("%s:%s" % (name.upper(), reg(name)) for name in self.REGISTERS) + " " + \
                   "".join(flag(name, letter) for name, letter in zip(self.FLAGS, "szapc"))

    def is_subroutine_call(self, binary_addr):
        return False

    def is_branch_to(self, binary_addr, target_runtime_addr):
        c = classification.get_classification(binary_addr)

        # TODO: hacky use of isinstance()
        if isinstance(c, self.OpcodeConditionalBranch):
            return c._target(binary_addr) == target_runtime_addr
        return False

    def label_maker(self, lmd):
        # Label return1, return2 etc
        memory_binary = session.current().memory.binary
        if config.get_label_return_instructions_numerically():
            # Only if the current label is autogenerated
            if lmd.is_autogenerated:
                defined_at_binary_addr, _ = movemanager.r2b(lmd.defined_as_runtime_addr, lmd.defined_in_move_id)
                c = classification.get_classification(defined_at_binary_addr)
                if c is not None:
                    if isinstance(c, self.Opcode):
                        by = memory_binary[defined_at_binary_addr]
                        if by == OPCODE_RET:
                            if not defined_at_binary_addr in self.return_array:
                                self.return_index += 1
                                self.return_array[defined_at_binary_addr] = self.return_index

                            lmd.name = "return_{0}".format(self.return_array[defined_at_binary_addr])
