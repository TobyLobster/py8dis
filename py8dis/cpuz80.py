"""
The Z80 CPU.

CpuZ80 decodes, traces and follows the state of Z80 code. It's chosen with
load(..., "Z80") (see commands.py), and its output is for z88dk-z80asm or
sjasmplus.

Decoding. The Z80 has prefixes: CB (rotates, shifts, BIT, RES and SET), ED
(the extra instructions, e.g. the block moves, IN r,(C) and 16 bit ADC and
SBC), and DD and FD, which make the next instruction use IX or IY in place of
HL, and (IX+d) or (IY+d), with a displacement byte d, in place of (HL). DD CB
and FD CB are the CB instructions on (IX+d) and (IY+d), with the
displacement before the opcode: DD CB d op.

Rather than listing them all, the opcode table is made from the fields of
each opcode (as described in "Decoding Z80 opcodes": x = bits 7-6, y = bits
5-3, z = bits 2-0, p = bits 5-4, q = bit 3), for each prefix: none (_main()),
CB (_cb()), ED (_ed()), DD and FD (_main() with IX or IY), and DD CB and FD CB
(_index_cb()). Each gives a Spec: the opcode's length, mnemonic and operands
(text, and Part objects for the bytes that come from the instruction, e.g.
Imm8 for an immediate value), how control continues after it (FLOW_...), its
cycles, and whether it's undocumented. opcode_specs() collects them, and
CpuZ80 makes an Opcode object from each, in a table for each prefix;
CpuZ80.opcode_at() finds the right one from the prefix and opcode bytes.

Tracing. cpu.Cpu, the base class, follows the code from the entry points:
it finds each instruction's Opcode with opcode_at(), classifies its bytes as
code, and calls the Opcode's update_references() and disassemble(), which
gives the binary addresses to trace next from its kind (FLOW_...). A CALL or
RST is traced as a call: on at the return address (unless a subroutine hook
says otherwise) and at the subroutine. CpuZ80 also finds code from what the
code does (find_entry_points_from_effects(), e.g. a return address pushed
onto the stack), comments calls to subroutines (find_subroutine_calls()),
and comments instructions whose results are never used
(find_redundant_instructions()).

The CPU state. What's known for certain about the registers and flags after
each instruction is followed by cpuz80state.py (see Opcode.update_cpu_state()
and cpuz80state.update_state(), which decodes each opcode's fields again).

The undocumented opcodes are traced as what they do. Whether each is written
as an instruction or as data bytes is up to the assembler (see
Assembler.undocumented_z80_accepted()): e.g. z88dk-z80asm assembles 'ld
ixh,a' and 'sll b', but not the duplicates (e.g. ED 4C, a second NEG).
"""

import collections

import classification
import config
import cpu
import cpuz80state
import disassembly
import expression
import memorymanager
import movemanager
import output
import session
import utils
from binaryaddrtype import BinaryAddrType
from memorymanager import RuntimeAddr
from align import Align


# RET, whose labels can be named return_1, return_2 etc. (see
# CpuZ80.label_maker())
OPCODE_RET = 0xc9

# The kinds of undocumented opcode (see Assembler.undocumented_z80_accepted())
INDEX_HALVES        = "index_halves"         # IXH, IXL, IYH, IYL, e.g. 'ld ixh,a'
SLL                 = "sll"                  # CB 30-37 (also called SLI or SL1)
INDEXED_CB_REGISTER = "indexed_cb_register"  # DD CB d op that also copies the result to a register, e.g. 'rlc (ix+2),b'
IN_F_C              = "in_f_c"               # ED 70, 'in f,(c)'
OUT_C_0             = "out_c_0"              # ED 71, 'out (c),0'
DUPLICATE           = "duplicate"            # a second encoding of an instruction (e.g. ED 4C, NEG)
NOP                 = "nop"                  # an ED opcode that does nothing
IGNORED_PREFIX      = "ignored_prefix"       # DD or FD before an instruction that doesn't use HL

UNDOCUMENTED_KINDS = (INDEX_HALVES, SLL, INDEXED_CB_REGISTER, IN_F_C, OUT_C_0, DUPLICATE, NOP, IGNORED_PREFIX)

# How control continues after an instruction (Opcode.kind). (RET cc is
# FLOW_NEXT, since the code may continue after it.)
FLOW_NEXT    = "next"       # to the next instruction
FLOW_JP      = "jp"         # jp nn
FLOW_JP_CC   = "jp_cc"      # jp cc,nn
FLOW_JR      = "jr"         # jr e
FLOW_JR_CC   = "jr_cc"      # jr cc,e and djnz e
FLOW_CALL    = "call"       # call nn, call cc,nn
FLOW_RST     = "rst"        # rst n
FLOW_RET     = "ret"        # ret, reti, retn
FLOW_JP_IND  = "jp_ind"     # jp (hl), jp (ix), jp (iy)

# Operand parts (in Opcode.operands, as well as plain text such as 'a,')
class Part:
    """A part of an operand that comes from the instruction's bytes, at
    'offset' from its first byte (counting any prefix). Each subclass is a
    kind of part, with its 'size' in bytes."""
    def __init__(self, offset):
        self.offset = offset

class Imm8(Part):
    """An 8 bit immediate value, e.g. 'ld a,n'."""
    size = 1
class Imm16(Part):
    """A 16 bit immediate value, e.g. 'ld hl,nn'."""
    size = 2
class Addr(Part):
    """A 16 bit address in brackets, e.g. 'ld a,(nn)'."""
    size = 2
class Target(Part):
    """A 16 bit jump or call address, e.g. 'jp nn'."""
    size = 2
class Rel(Part):
    """A relative jump's offset, e.g. 'jr e'."""
    size = 1
class Port(Part):
    """An I/O port in brackets, e.g. 'in a,(n)'."""
    size = 1
class Index(Part):
    """An indexed address, e.g. '(ix+d)': the displacement d, and the
    'register' ("ix" or "iy")."""
    size = 1
    def __init__(self, offset, register):
        super().__init__(offset)
        self.register = register

def _signed(n):
    """A byte as a signed number (-128 to 127), e.g. a relative jump's
    offset or an index register's displacement."""
    return n - 0x100 if n >= 0x80 else n

class Spec:
    """An opcode, as made by the decoding functions below: its 'length' in
    bytes (including any prefix, displacement or immediate value); its
    'mnemonic' (the first word of 'text'); its 'operands', which are the rest
    of 'text' and then 'operands', a mix of text and Part objects that are
    written one after the other (e.g. "ld a,(" with [Addr(1), ")"] has the
    operands ['a,(', Addr(1), ')']); its 'kind' (FLOW_...); its 'cycles', as
    text (e.g. "7/12" for a conditional jump, not taken or taken); and
    'undocumented', None or the kind of undocumented opcode it is (see
    UNDOCUMENTED_KINDS), or a tuple of kinds."""
    def __init__(self, length, text, operands=(), kind=FLOW_NEXT, cycles="", undocumented=None):
        self.length = length
        words = text.split(" ", 1)
        self.mnemonic = words[0]
        self.operands = ([words[1]] if len(words) > 1 else []) + list(operands)
        self.kind = kind
        self.cycles = cycles
        self.undocumented = undocumented

# The tables of "Decoding Z80 opcodes", by the opcode's fields: R, the 8 bit
# registers (by y or z); RP and RP2, the register pairs (by p; RP2 for PUSH
# and POP); CC, the conditions (by y); ALU, the arithmetic and logic
# operations on A, with any first operand (by y); ROT, the CB opcodes'
# rotates and shifts (by y); and BLOCK, the ED opcodes' block instructions
# (by y - 4, then z)
R   = ("b", "c", "d", "e", "h", "l", "(hl)", "a")
RP  = ("bc", "de", "hl", "sp")
RP2 = ("bc", "de", "hl", "af")
CC  = ("nz", "z", "nc", "c", "po", "pe", "p", "m")
ALU = ("add a,", "adc a,", "sub ", "sbc a,", "and ", "xor ", "or ", "cp ")
ROT = ("rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl")
BLOCK = (("ldi", "cpi", "ini", "outi"), ("ldd", "cpd", "ind", "outd"),
         ("ldir", "cpir", "inir", "otir"), ("lddr", "cpdr", "indr", "otdr"))


def _main(op, index=None):
    """The unprefixed opcode 'op', or with an index register (index "ix"
    after DD, or "iy" after FD) in place of HL, as a Spec. With an index
    register, returns None if the opcode doesn't use HL, H, L or (HL), since
    the prefix then has no effect. Also returns None for the prefixes
    themselves (CB, DD, ED and FD).

    With an index register, (HL) becomes (IX+d), with the displacement after
    the opcode, and H and L become the undocumented IXH and IXL (or IYH and
    IYL)."""

    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    p, q = y >> 1, y & 1
    o = 1 if index else 0               # the offset of the opcode byte

    def plain(text, length=1, cycles=4, kind=FLOW_NEXT, operands=()):
        """An instruction that doesn't use HL: None after a prefix, which
        has no effect on it."""
        if index:
            return None
        return Spec(length, text, operands, kind, str(cycles))

    def with_hl(text, length, cycles, index_cycles, operands=(), kind=FLOW_NEXT):
        """An instruction that uses HL (as written in 'text'), with IX or IY
        in its place after a prefix, which makes it a byte longer and take
        'index_cycles'. (Every "hl" in the text is replaced, so e.g. 'add
        hl,hl' becomes 'add ix,ix'.)"""
        if index:
            operands = [x.replace("hl", index) if isinstance(x, str) else x for x in operands]
            return Spec(o + length, text.replace("hl", index), operands, kind, str(index_cycles))
        return Spec(length, text, operands, kind, str(cycles))

    def reg8(i):
        """Register i, with IXH/IXL (or IYH/IYL) for H/L after a prefix."""
        if index and i in (4, 5):
            return index + "hl"[i - 4]
        return R[i]

    # x == 0: NOP, EX AF,AF', DJNZ and JR; LD rp,nn and ADD HL,rp; the loads
    # through (BC), (DE) and (nn); INC and DEC; LD r,n; and RLCA ... CCF
    if x == 0:
        if z == 0:
            if y == 0:
                return plain("nop")
            if y == 1:
                return plain("ex af,af'")
            if y == 2:
                return plain("djnz", 2, "8/13", FLOW_JR_CC, [Rel(1)])
            if y == 3:
                return plain("jr", 2, 12, FLOW_JR, [Rel(1)])
            return plain("jr " + CC[y - 4] + ",", 2, "7/12", FLOW_JR_CC, [Rel(1)])
        if z == 1:
            if q == 0:
                if p == 2:
                    return with_hl("ld hl,", 3, 10, 14, [Imm16(o + 1)])
                return plain("ld " + RP[p] + ",", 3, 10, operands=[Imm16(1)])
            return with_hl("add hl," + RP[p], 1, 11, 15)
        if z == 2:
            if p == 2:
                if q == 0:
                    return with_hl("ld (", 3, 16, 20, [Addr(o + 1), "),hl"])
                return with_hl("ld hl,(", 3, 16, 20, [Addr(o + 1), ")"])
            if p == 3:
                if q == 0:
                    return plain("ld (", 3, 13, operands=[Addr(1), "),a"])
                return plain("ld a,(", 3, 13, operands=[Addr(1), ")"])
            rp = "(bc)" if p == 0 else "(de)"
            return plain("ld " + rp + ",a" if q == 0 else "ld a," + rp, 1, 7)
        if z == 3:
            mnemonic = "inc " if q == 0 else "dec "
            if p == 2:
                return with_hl(mnemonic + "hl", 1, 6, 10)
            return plain(mnemonic + RP[p], 1, 6)
        if z in (4, 5):
            mnemonic = "inc" if z == 4 else "dec"
            if y == 6:
                if index:
                    return Spec(3, mnemonic, ["(", Index(2, index), ")"], cycles="23")
                return Spec(1, mnemonic + " (hl)", cycles="11")
            if index and y in (4, 5):
                return Spec(2, mnemonic + " " + reg8(y), cycles="8", undocumented=INDEX_HALVES)
            return plain(mnemonic + " " + R[y])
        if z == 6:
            if y == 6:
                if index:
                    return Spec(4, "ld", ["(", Index(2, index), "),", Imm8(3)], cycles="19")
                return Spec(2, "ld (hl),", [Imm8(1)], cycles="10")
            if index and y in (4, 5):
                return Spec(3, "ld " + reg8(y) + ",", [Imm8(2)], cycles="11", undocumented=INDEX_HALVES)
            return plain("ld " + R[y] + ",", 2, 7, operands=[Imm8(1)])
        return plain(("rlca", "rrca", "rla", "rra", "daa", "cpl", "scf", "ccf")[y])

    # x == 1: LD r,r' (HALT is in place of LD (HL),(HL))
    if x == 1:
        if y == 6 and z == 6:
            return plain("halt")
        if y == 6 or z == 6:
            # (With an index register, the other register stays H or L)
            if index:
                if y == 6:
                    return Spec(3, "ld", ["(", Index(2, index), ")," + R[z]], cycles="19")
                return Spec(3, "ld " + R[y] + ",", ["(", Index(2, index), ")"], cycles="19")
            return Spec(1, "ld %s,%s" % (R[y], R[z]), cycles="7")
        if index and (y in (4, 5) or z in (4, 5)):
            return Spec(2, "ld %s,%s" % (reg8(y), reg8(z)), cycles="8", undocumented=INDEX_HALVES)
        return plain("ld %s,%s" % (R[y], R[z]))

    # x == 2: the arithmetic and logic operations on A with a register
    if x == 2:
        if z == 6:
            if index:
                return Spec(3, ALU[y] + "(", [Index(2, index), ")"], cycles="19")
            return Spec(1, ALU[y] + "(hl)", cycles="7")
        if index and z in (4, 5):
            return Spec(2, ALU[y] + reg8(z), cycles="8", undocumented=INDEX_HALVES)
        return plain(ALU[y] + R[z])

    # x == 3: RET cc; POP, RET, EXX, JP (HL) and LD SP,HL; JP cc; JP, OUT
    # (n),A, IN A,(n), EX (SP),HL, EX DE,HL, DI and EI (and the CB prefix);
    # CALL cc; PUSH and CALL (and the DD, ED and FD prefixes); the
    # arithmetic and logic operations with an immediate value; and RST
    if z == 0:
        return plain("ret " + CC[y], 1, "5/11")
    if z == 1:
        if q == 0:
            if p == 2:
                return with_hl("pop hl", 1, 10, 14)
            return plain("pop " + RP2[p], 1, 10)
        if p == 0:
            return plain("ret", 1, 10, FLOW_RET)
        if p == 1:
            return plain("exx")
        if p == 2:
            return with_hl("jp (hl)", 1, 4, 8, kind=FLOW_JP_IND)
        return with_hl("ld sp,hl", 1, 6, 10)
    if z == 2:
        return plain("jp " + CC[y] + ",", 3, 10, FLOW_JP_CC, [Target(1)])
    if z == 3:
        if y == 0:
            return plain("jp", 3, 10, FLOW_JP, [Target(1)])
        if y == 1:
            return None                 # (the CB prefix)
        if y == 2:
            return plain("out (", 2, 11, operands=[Port(1), "),a"])
        if y == 3:
            return plain("in a,(", 2, 11, operands=[Port(1), ")"])
        if y == 4:
            return with_hl("ex (sp),hl", 1, 19, 23)
        return plain(("ex de,hl", "di", "ei")[y - 5])
    if z == 4:
        return plain("call " + CC[y] + ",", 3, "10/17", FLOW_CALL, [Target(1)])
    if z == 5:
        if q == 0:
            if p == 2:
                return with_hl("push hl", 1, 11, 15)
            return plain("push " + RP2[p], 1, 11)
        if p == 0:
            return plain("call", 3, 17, FLOW_CALL, [Target(1)])
        return None                     # (the DD, ED and FD prefixes)
    if z == 6:
        return plain(ALU[y].rstrip(), 2, 7, operands=[Imm8(1)])
    return plain("rst $%02x" % (y * 8), 1, 11, FLOW_RST)


def _cb(op):
    """The opcode CB op: a rotate or shift (x = 0, which y chooses), BIT (x
    = 1), RES (2) or SET (3) of bit y, of register z (6 is (HL)). CB 30-37
    is the undocumented SLL."""
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    hl = z == 6
    if x == 0:
        return Spec(2, ROT[y] + " " + R[z], cycles="15" if hl else "8", undocumented=SLL if y == 6 else None)
    mnemonic = ("bit", "res", "set")[x - 1]
    return Spec(2, "%s %d,%s" % (mnemonic, y, R[z]), cycles=("12" if x == 1 else "15") if hl else "8")


def _index_cb(op, index):
    """The opcode DD CB d op (index "ix") or FD CB d op ("iy"): the CB
    instruction on (IX+d) or (IY+d), with the displacement at offset 2. The
    documented ones have register field z = 6; with any other, the result is
    also copied to that register (undocumented), except for BIT, where it's
    a duplicate."""
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    if x == 1:
        # (Every register field is the same instruction)
        return Spec(4, "bit %d,(" % y, [Index(2, index), ")"], cycles="20", undocumented=None if z == 6 else DUPLICATE)
    text = ROT[y] + " (" if x == 0 else "%s %d,(" % (("res", "set")[x - 2], y)
    undocumented = [SLL] if x == 0 and y == 6 else []
    if z == 6:
        operands = [Index(2, index), ")"]
    else:
        # The result is also copied to a register
        operands = [Index(2, index), ")," + R[z]]
        undocumented.append(INDEXED_CB_REGISTER)
    return Spec(4, text, operands, cycles="23", undocumented=tuple(undocumented) if undocumented else None)


def _ed(op):
    """The opcode ED op: x = 1 is IN and OUT with (C), 16 bit ADC and SBC,
    16 bit loads with (nn), NEG, RETN, RETI, IM, the loads of I and R, RRD
    and RLD; x = 2 the block instructions (LDI, CPIR etc.). Many have
    undocumented duplicates (e.g. ED 4C, another NEG), and the opcodes that
    aren't instructions do nothing (an undocumented NOP)."""
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    p, q = y >> 1, y & 1
    if x == 1:
        if z == 0:
            if y == 6:
                return Spec(2, "in f,(c)", cycles="12", undocumented=IN_F_C)
            return Spec(2, "in %s,(c)" % R[y], cycles="12")
        if z == 1:
            if y == 6:
                return Spec(2, "out (c),0", cycles="12", undocumented=OUT_C_0)
            return Spec(2, "out (c),%s" % R[y], cycles="12")
        if z == 2:
            return Spec(2, "%s hl,%s" % ("sbc" if q == 0 else "adc", RP[p]), cycles="15")
        if z == 3:
            undocumented = DUPLICATE if p == 2 else None          # (ld (nn),hl and ld hl,(nn))
            if q == 0:
                return Spec(4, "ld (", [Addr(2), ")," + RP[p]], cycles="20", undocumented=undocumented)
            return Spec(4, "ld %s,(" % RP[p], [Addr(2), ")"], cycles="20", undocumented=undocumented)
        if z == 4:
            return Spec(2, "neg", cycles="8", undocumented=None if y == 0 else DUPLICATE)
        if z == 5:
            if y == 1:
                return Spec(2, "reti", kind=FLOW_RET, cycles="14")
            return Spec(2, "retn", kind=FLOW_RET, cycles="14", undocumented=None if y == 0 else DUPLICATE)
        if z == 6:
            mode = (0, 0, 1, 2, 0, 0, 1, 2)[y]
            return Spec(2, "im %d" % mode, cycles="8", undocumented=None if y in (0, 2, 3) else DUPLICATE)
        if y < 6:
            return Spec(2, ("ld i,a", "ld r,a", "ld a,i", "ld a,r", "rrd", "rld")[y], cycles="18" if y >= 4 else "9")
    elif x == 2 and z <= 3 and y >= 4:
        mnemonic = BLOCK[y - 4][z]
        return Spec(2, mnemonic, cycles="16/21" if y >= 6 else "16")
    return Spec(2, "nop", cycles="8", undocumented=NOP)


def opcode_specs():
    """All the opcodes, as a dictionary from their bytes (a tuple of the
    prefix and opcode bytes, without any displacement or immediate value:
    e.g. (0xdd, 0xcb, 0x06) for DD CB d 06) to Spec. The prefixes on their
    own (CB, DD, ED and FD) aren't in it, nor are DD and FD before an opcode
    they have no effect on (see CpuZ80.ignored_prefix)."""
    result = {}
    for op in range(256):
        spec = _main(op)
        if spec is not None:
            result[(op,)] = spec
        result[(0xcb, op)] = _cb(op)
        result[(0xed, op)] = _ed(op)
        for prefix, index in ((0xdd, "ix"), (0xfd, "iy")):
            spec = _main(op, index)
            if spec is not None:
                result[(prefix, op)] = spec
            result[(prefix, 0xcb, op)] = _index_cb(op, index)
    return result


class CpuZ80(cpu.Cpu):
    """The Z80 CPU (see the module docstring).

    Its opcode tables, each of Opcode objects by opcode byte, are:
    'opcodes' (unprefixed), 'cb_opcodes', 'ed_opcodes', 'index_opcodes'
    and 'index_cb_opcodes' (each by DD or FD, then the opcode); and
    'ignored_prefix' (by DD or FD) is the Opcode for a prefix that has no
    effect on the instruction after it, which is traced as a one byte
    instruction of its own. 'return_index' and 'return_array' number the
    RET instructions' labels (see label_maker()), and 'indent_level_dict'
    gives an instruction's extra indent (see Opcode.indent())."""

    def __init__(self):
        """Make the opcode tables, and add the Z80's code analysis (see
        find_subroutine_calls(), find_redundant_instructions() and
        find_entry_points_from_effects())."""
        super().__init__()

        # For labelling ret instructions numerically: the number of the
        # last one named, and each one's number by binary address
        self.return_index = 0
        self.return_array = {}

        # indent_level_dict has binary addresses as the keys, and indent amounts as the values.
        self.indent_level_dict = collections.defaultdict(int)

        # The opcodes, by prefix: self.opcodes has the unprefixed ones (the
        # prefixes aren't in it). Each key from opcode_specs() says which
        # table it goes in: one byte unprefixed, two bytes after CB, ED, DD
        # or FD, and three bytes after DD CB or FD CB.
        self.opcodes = {}
        self.cb_opcodes = {}
        self.ed_opcodes = {}
        self.index_opcodes = {0xdd: {}, 0xfd: {}}
        self.index_cb_opcodes = {0xdd: {}, 0xfd: {}}
        for key, spec in opcode_specs().items():
            opcode = self.Opcode(key, spec)
            if len(key) == 1:
                self.opcodes[key[0]] = opcode
            elif key[0] == 0xcb:
                self.cb_opcodes[key[1]] = opcode
            elif key[0] == 0xed:
                self.ed_opcodes[key[1]] = opcode
            elif len(key) == 2:
                self.index_opcodes[key[0]][key[1]] = opcode
            else:
                self.index_cb_opcodes[key[0]][key[2]] = opcode
        self.ignored_prefix = {prefix: self.Opcode((prefix,), Spec(1, "nop", cycles="4", undocumented=IGNORED_PREFIX)) for prefix in (0xdd, 0xfd)}

        # The runtime addresses called by RST that have been traced (see
        # label_maker())
        self.rst_targets = set()

        # Calls to the subroutines defined with subroutine() (see
        # find_subroutine_calls())
        self.code_analysis_fns.append(self.find_subroutine_calls)
        # Instructions whose results are never used (see
        # find_redundant_instructions())
        self.code_analysis_fns.append(self.find_redundant_instructions)

        # Functions that find code addresses from what the code does, each
        # returning a list of (the binary address of an instruction, of its
        # 16 bit operand, the code address that holds, and a comment for the
        # instruction with '%s' for the address's label, or None), e.g.
        # spectrum.py's for a channel's routine (see
        # find_entry_points_from_effects())
        self.code_pointer_finders = [self.pushed_return_addresses]
        # (The operands already found)
        self.code_pointer_operands = set()

    def find_subroutine_calls(self):
        """Call the hook of each subroutine defined with subroutine() for
        each instruction that calls it (CALL, RST or JP, conditional or
        not), or that is at its address, with the runtime address of the
        instruction, the CPU state before it (a CpuState) and the
        subroutine. (See the 'hook' of commands.subroutine(), and
        default_subroutine_hook().)

        It goes through the code in address order, taking the state before
        each instruction from cpu_states (the state after the one before),
        with nothing known after data, a block end, or at a label."""
        subroutines = collections.defaultdict(list)
        for subroutine in session.current().trace.subroutines_list:
            if subroutine.hook_function is not None:
                subroutines[subroutine.runtime_addr].append(subroutine)
        if not subroutines:
            return
        state = self.CpuState()
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = range_start
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is None or not c.is_code(binary_addr):
                    state = self.CpuState()
                    binary_addr += 1 if c is None else c.length()
                    continue
                runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
                if runtime_addr in session.current().labels.labels:
                    # (Code can come here from elsewhere)
                    state = self.CpuState()
                found = list(subroutines.get(runtime_addr, []))
                if c.kind in (FLOW_CALL, FLOW_RST, FLOW_JP, FLOW_JP_CC):
                    found += subroutines.get(c.target(binary_addr), [])
                for subroutine in found:
                    subroutine.hook_function(runtime_addr, state, subroutine)
                state = self.CpuState() if c.is_block_end() else (self.cpu_states[binary_addr] or self.CpuState())
                binary_addr += c.length()

    # ********************************************************************************************
    # Redundant instructions: those whose results are never used

    # The instructions that can be redundant (see _effects()): they only
    # change registers and flags, and perhaps read memory
    _REDUNDANT_MNEMONICS = {"ld", "inc", "dec", "add", "adc", "sub", "sbc", "and", "xor", "or", "cp",
                            "rlca", "rrca", "rla", "rra", "daa", "cpl", "scf", "ccf", "neg",
                            "rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl", "bit", "res", "set", "ex"}

    def straight_runs(self):
        """The code, as runs of instructions (lists of binary addresses, in
        address order) that the code runs straight through: each ends at
        the end of a block (e.g. RET or JP), or before an instruction that
        other code jumps to (or an entry point). (A CALL doesn't end a
        run.)"""
        labels = session.current().labels.labels
        run = []
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = range_start
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if not isinstance(c, self.Opcode):
                    if run:
                        yield run
                        run = []
                    binary_addr += 1 if c is None or c is classification.INSIDE_A_CLASSIFICATION else c.length()
                    continue
                label = labels.get(movemanager.b2r(memorymanager.BinaryAddr(binary_addr)))
                if run and ((label is not None and label.references) or binary_addr in self.explicit_entry_points):
                    yield run
                    run = []
                run.append(binary_addr)
                binary_addr += c.length()
                if c.is_block_end():
                    yield run
                    run = []
            if run:
                yield run
                run = []

    class _TrackingState(cpuz80state.CpuState):
        """A CpuState that records which registers and flags an instruction
        reads and writes (see _effects()): 'reads' and 'writes' are sets of
        their names, and 'cleared' is True if the instruction forgot
        everything (a CALL or RST)."""
        def __init__(self):
            super().__init__()
            self.reads = set()
            self.writes = set()
            self.cleared = False

        def clear(self, *, pessimistic_only=False):
            """Forget everything, noting that update_state() did. (Not when
            CpuState.__init__() clears the new state, before 'reads' is
            made.)"""
            super().clear()
            if hasattr(self, "reads"):
                self.cleared = True

        def __getitem__(self, key):
            """A register or flag's value, noting that it's read."""
            self.reads.add(key)
            return super().__getitem__(key)

        def __setitem__(self, key, value):
            """Set a register or flag, noting that it's written."""
            self.writes.add(key)
            super().__setitem__(key, value)

    def _effects(self, c, binary_addr):
        """What the instruction c (an Opcode) at binary_addr does to the
        registers and flags, for find_redundant_instructions(): (reads,
        writes, whether it could be redundant), with reads and writes sets
        of names from cpuz80state.ALL. These are found by running it with
        nothing known (see cpuz80state.update_state()), noting what's read
        and written, and adding the registers its operands name (see
        _operand_reads()). A jump, call or return reads everything."""
        all_resources = set(cpuz80state.ALL)
        if c.kind != FLOW_NEXT or c.mnemonic == "ret":
            # (A jump, call or return, including RET cc: what comes after
            # could use anything)
            return all_resources, set(), False
        memory_binary = session.current().memory.binary
        state = self._TrackingState()
        if len(c.key) == 3:
            # (DD CB d op: the displacement)
            operands = [memory_binary[binary_addr + 2]]
        else:
            operands = [memory_binary[binary_addr + i] for i in range(len(c.key), c.length())]
        cpuz80state.update_state(state, c.key, operands)
        if state.cleared:
            return all_resources, set(), False
        reads, writes = set(state.reads), set(state.writes)
        # (What's not tracked isn't read by update_state(), e.g. the
        # register a store stores, or the address in HL, so those are read
        # too)
        reads |= self._operand_reads(c)
        if c.mnemonic in ("xor", "sub") and c.operands == ["a"]:
            reads.discard("a")                  # (XOR A and SUB A are 0, whatever A is)

        # Whether it can be redundant: it only changes registers and flags,
        # and doesn't write memory; it may read memory, but not I/O
        if c.mnemonic not in self._REDUNDANT_MNEMONICS or c.undocumented in (IGNORED_PREFIX, NOP):
            return reads, writes, False
        first = c.operands[0] if c.operands else ""
        if isinstance(first, str) and first.startswith("(") and c.mnemonic in ("ld", "inc", "dec", "rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl"):
            return reads, writes, False         # (It writes memory, e.g. 'ld (hl),a' or 'inc (hl)')
        if c.mnemonic in ("res", "set") and any(isinstance(x, str) and "(" in x for x in c.operands):
            return reads, writes, False         # (e.g. 'set 3,(hl)')
        if c.mnemonic == "ld" and c.operands and c.operands[0] in ("i,a", "r,a"):
            return reads, writes, False         # (I is the interrupt vector, R the refresh register)
        if c.mnemonic in ("rlc", "rrc", "rl", "rr", "sla", "sra", "sll", "srl", "res", "set") and c.part(Index) is not None:
            return reads, writes, False         # (The indexed forms write memory)
        if c.mnemonic == "ex" and c.operands != ["de,hl"]:
            return reads, writes, False         # (EX AF,AF' swaps with the other set; EX (SP),HL writes memory)
        io_ranges = session.current().disassembly.io_ranges
        addr = c.part(Addr)
        if addr is not None:
            target = memorymanager.get_u16_binary(binary_addr + addr.offset)
            if any(start <= target + 1 and target < end for start, end in io_ranges):
                return reads, writes, False
        elif io_ranges and (c.part(Index) is not None or any(isinstance(x, str) and ("(hl)" in x or "(bc)" in x or "(de)" in x) for x in c.operands)):
            # (It could be reading I/O, at an address that isn't known)
            return reads, writes, False
        return reads, writes, True

    # The registers named in an operand, and what they are, as names in
    # cpuz80state.ALL (e.g. 'hl' is H and L, and 'af' is A and the flags)
    _OPERAND_REGISTERS = {
        "a": ("a",), "b": ("b",), "c": ("c",), "d": ("d",), "e": ("e",), "h": ("h",), "l": ("l",),
        "af": ("a",) + cpuz80state.FLAGS, "bc": ("b", "c"), "de": ("d", "e"), "hl": ("h", "l"), "sp": ("sp",),
        "ix": ("ixh", "ixl"), "iy": ("iyh", "iyl"), "ixh": ("ixh",), "ixl": ("ixl",), "iyh": ("iyh",), "iyl": ("iyl",),
        "i": ("i",),
    }
    # The block instructions, which use BC, DE and HL (and A, for CPI etc.)
    _BLOCK_MNEMONICS = {"ldi", "ldir", "ldd", "lddr", "cpi", "cpir", "cpd", "cpdr",
                        "ini", "inir", "ind", "indr", "outi", "otir", "outd", "otdr"}

    def _operand_reads(self, c):
        """The registers (and flags) the instruction reads, from its operands:
        each register named, except the one a load (LD, POP or IN) writes,
        and the registers it uses implicitly (e.g. SP for PUSH).

        It writes the operand as text (an (IX+d) as '(ix+d)', and any other
        part as 'n'), splits it at the commas, and looks up each name in
        each piece in _OPERAND_REGISTERS."""
        import re
        text = "".join(x if isinstance(x, str) else ("(%s+d)" % x.register if isinstance(x, Index) else "n") for x in c.operands).lower()
        operands = text.split(",") if text else []
        result = set()
        for i, operand in enumerate(operands):
            if i == 0 and c.mnemonic in ("ld", "pop", "in") and "(" not in operand:
                continue                        # (The register it loads)
            for name in re.findall(r"[a-z]+", operand):
                if operand.strip() == "(c)" and name == "c":
                    result |= {"b", "c"}        # (The port is BC)
                else:
                    result |= set(self._OPERAND_REGISTERS.get(name, ()))
        if c.mnemonic in ("push", "pop") or "(sp)" in text:
            result.add("sp")
        if c.mnemonic in self._BLOCK_MNEMONICS:
            result |= {"a", "b", "c", "d", "e", "h", "l"}
        # (RLD and RRD use A and (HL). For IN this is more than it reads (H
        # and L, and A for IN r,(C)), which only means that fewer
        # instructions before it are found to be redundant.)
        if c.mnemonic in ("rld", "rrd", "in"):
            result |= {"a", "h", "l"}           # (IN A,(n) puts A on the address bus)
        return result

    def find_redundant_instructions(self):
        """Comment each instruction whose results are never used: in a
        straight run of code (see straight_runs()), each register and flag
        it changes is changed again before anything reads it, e.g. 'ld
        a,(hl)' just before 'pop af'. Only instructions that just change
        registers and flags can be redundant (not a store, e.g. 'ld (hl),a',
        or IN, or a read of I/O, see commands.io_range()). The end of a run,
        a CALL, a jump or a return counts as reading everything. (See
        config.set_redundant_instruction_comments().)"""
        if not config.get_redundant_instruction_comments():
            return
        # Go backwards through each run, keeping the registers and flags
        # whose values may be read later ('live'): all of them at the end of
        # the run.
        for run in self.straight_runs():
            live = set(cpuz80state.ALL)
            for binary_addr in reversed(run):
                c = classification.get_classification(binary_addr)
                reads, writes, candidate = self._effects(c, binary_addr)
                if candidate and writes and not (writes & live):
                    disassembly.comment_binary(memorymanager.BinaryAddr(binary_addr), "Redundant instruction?", align=Align.INLINE, word_wrap=False, auto_generated=True)
                    continue
                live = (live - writes) | reads

    # ********************************************************************************************
    # Code addresses found from what the code does

    def find_entry_points_from_effects(self):
        """Trace the code addresses that code_pointer_finders find (e.g. a
        return address pushed with 'ld hl,nn : push hl'), each naming the
        address in the instruction that loads it.

        An address that's loaded, and isn't data or inside an instruction,
        is added as an explicit entry point (if it isn't already code), and
        the operand gets the address's label as an expression (unless it
        has one already), with the finder's comment, if any, on the
        instruction. Each operand is only done once, since this is called
        again after each time the entry points found are traced (see
        cpu.Cpu.trace())."""
        for finder in self.code_pointer_finders:
            for instruction_binary_addr, operand_binary_addr, target, description in finder():
                if operand_binary_addr in self.code_pointer_operands:
                    continue
                self.code_pointer_operands.add(operand_binary_addr)
                target = RuntimeAddr(target)
                binary_addr, move_id = movemanager.r2b(target)
                if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr, 1):
                    continue
                c = classification.get_classification(binary_addr)
                if c is not None and not isinstance(c, self.Opcode):
                    # (Data, or inside an instruction: not code after all)
                    continue
                if c is None:
                    self.add_entry(binary_addr, target, move_id, None, explicit=True)
                label = disassembly.get_label(target, operand_binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
                classification.add_expression(operand_binary_addr, label, force=False, auto_generated=False)
                if description is not None:
                    disassembly.comment(movemanager.b2r(memorymanager.BinaryAddr(instruction_binary_addr)), utils.LazyString(description, label),
                                        align=Align.INLINE, word_wrap=False, auto_generated=True)

    # Instructions that load a 16 bit register with a value, 'ld rr,nn', by
    # their bytes, and the register
    _LD_RR_NN = {(0x01,): "bc", (0x11,): "de", (0x21,): "hl", (0xdd, 0x21): "ix", (0xfd, 0x21): "iy"}

    # The most instructions pushed_return_addresses() looks through after
    # each push, and the deepest it follows the stack
    _RETURN_SEARCH_LIMIT = 1000
    _RETURN_SEARCH_DEPTH = 16

    def pushed_return_addresses(self):
        """Return addresses pushed onto the stack, 'ld rr,nn' then 'push rr'
        (e.g. so that a routine jumped to returns there). It's a return
        address if, following the code on from the PUSH (along every path,
        but not into calls, which are taken to return), a RET (or RET cc)
        is reached with it at the top of the stack, or the stack pointer is
        stored ('ld (nn),sp', so that it can be restored to return there,
        as the ZX Spectrum's ROM does with ERR_SP), and no path takes it
        off the stack another way first (POP, EX (SP), or a change to SP).
        A value that's pushed to be popped later is data, not an
        address.

        Only an 'ld rr,nn' just before its 'push rr', in the same straight
        run, is looked for. The result is as code_pointer_finders wants it
        (with no comment for the instruction)."""
        result = []
        for run in self.straight_runs():
            for first, second in zip(run, run[1:]):
                ld = classification.get_classification(first)
                push = classification.get_classification(second)
                register = self._LD_RR_NN.get(ld.key)
                if register is None or push.mnemonic != "push" or push.operands != [register]:
                    continue
                if self._returns_to_pushed_value(second + push.length()):
                    operand_binary_addr = memorymanager.BinaryAddr(first + ld.part(Imm16).offset)
                    result.append((first, operand_binary_addr, memorymanager.get_u16_binary(operand_binary_addr), None))
        return result

    def _returns_to_pushed_value(self, start):
        """Following the code from the binary address 'start', with a value
        just pushed, does it return to that value (see
        pushed_return_addresses())?

        It searches every path from 'start', keeping the number of values
        pushed on top of it ('depth'): a PUSH adds one (up to
        _RETURN_SEARCH_DEPTH, beyond which the path isn't followed), and a
        POP takes one off, or at depth 0 pops the value itself. Calls aren't
        followed (they're taken to return), nor is JP (HL), whose target
        isn't known. It stops looking once _RETURN_SEARCH_LIMIT (address,
        depth) pairs have been seen, with the answer so far."""
        todo = [(memorymanager.BinaryAddr(start), 0)]
        seen = set()
        returns = False
        while todo:
            binary_addr, depth = todo.pop()
            if (binary_addr, depth) in seen or len(seen) >= self._RETURN_SEARCH_LIMIT:
                continue
            seen.add((binary_addr, depth))
            c = classification.get_classification(binary_addr)
            if not isinstance(c, self.Opcode):
                continue
            mnemonic, operands = c.mnemonic, c.operands
            next_addr = memorymanager.BinaryAddr(binary_addr + c.length())
            if mnemonic == "push":
                if depth < self._RETURN_SEARCH_DEPTH:
                    todo.append((next_addr, depth + 1))
                continue
            if mnemonic == "pop":
                if depth == 0:
                    return False            # (Popped: it's data)
                todo.append((next_addr, depth - 1))
                continue
            if mnemonic in ("ret", "reti", "retn"):
                if depth == 0:
                    returns = True
                # (RET cc may not return: then the code goes on)
                if operands:
                    todo.append((next_addr, depth))
                continue
            if mnemonic == "ld" and len(operands) == 3 and operands[2] == "),sp":
                if depth == 0:
                    returns = True          # (ld (nn),sp: SP is kept, to return there later)
                    continue
                todo.append((next_addr, depth))
                continue
            if (mnemonic == "ex" and operands and str(operands[0]).startswith("(sp)")) or \
               (mnemonic in ("inc", "dec") and operands == ["sp"]) or \
               (mnemonic == "ld" and operands and str(operands[0]).startswith("sp,")):
                if depth == 0:
                    return False            # (It's used some other way)
                continue                    # (The stack isn't followed any further)
            if c.kind == FLOW_JP_IND:
                continue
            # Follow a jump to its target, and a conditional one on to the
            # next instruction too. (Anything else, including a call or RST,
            # goes on to the next instruction.)
            if c.kind in (FLOW_JP, FLOW_JR, FLOW_JP_CC, FLOW_JR_CC):
                target_binary_addr = movemanager.r2b(c.target(binary_addr))[0]
                if target_binary_addr is not None:
                    todo.append((target_binary_addr, depth))
                if c.kind in (FLOW_JP, FLOW_JR):
                    continue
            todo.append((next_addr, depth))
        return returns

    def default_subroutine_hook(self, runtime_addr, state, subroutine):
        """Comment a call to a subroutine (defined with subroutine()) with
        its title: the hook commands.subroutine() uses when it's given
        none (see find_subroutine_calls()). The subroutine's own first
        instruction isn't commented."""
        if subroutine.title and subroutine.runtime_addr != runtime_addr:
            disassembly.comment(runtime_addr, subroutine.title, align=Align.INLINE, word_wrap=False, auto_generated=True)

    def opcode_at(self, binary_addr):
        """The opcode at binary_addr (an Opcode), found from its prefix and
        opcode bytes, or None if those bytes aren't loaded. (The operand
        bytes are checked by cpu.Cpu.disassemble_instruction().) For DD CB
        d op, the opcode is the fourth byte. A DD or FD before an opcode it
        has no effect on (including another prefix, other than CB) is the
        ignored_prefix Opcode, a one byte instruction of its own."""
        memory_binary = session.current().memory.binary
        def byte(offset):
            """The byte at the offset, or None if it isn't loaded (or is
            past the top of memory)."""
            addr = binary_addr + offset
            return memory_binary[addr] if addr < 0x10000 else None

        op = byte(0)
        if op is None:
            return None
        if op in self.opcodes:
            return self.opcodes[op]
        op1 = byte(1)
        if op1 is None:
            return None
        if op == 0xcb:
            return self.cb_opcodes[op1]
        if op == 0xed:
            return self.ed_opcodes[op1]
        # DD or FD
        if op1 == 0xcb:
            op3 = byte(3)
            return None if op3 is None else self.index_cb_opcodes[op][op3]
        return self.index_opcodes[op].get(op1, self.ignored_prefix[op])

    def hook_subroutine(self, runtime_addr, name, hook):
        """Add a subroutine hook (see commands.hook_subroutine()): the
        subroutine at runtime_addr becomes an explicit entry point called
        'name', and a CALL or RST to it asks hook(target, caller) for the
        runtime address the code carries on at (see Opcode.disassemble())."""
        runtime_addr = RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        self.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, name, explicit=True)
        self.subroutine_hooks[runtime_addr] = hook

    def get_target_binary_addr_preferring_given_move_id(self, runtime_addr, specific_move_id):
        """Given an instruction's operand address (a runtime address), find
        its most likely binary address, for the current set of active move
        ids, as a list (empty if there isn't one). It's in specific_move_id
        (the instruction's own move) if data is loaded there; otherwise
        where movemanager.r2b() finds it, if that's loaded (or the
        instruction's move doesn't have the address at all); otherwise in
        the instruction's move anyway. Used for the address a call returns
        to (see Opcode.disassemble())."""
        binary_addr, _ = movemanager.r2b(runtime_addr, specific_move_id)
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr, 1):
            # (e.g. a jump from the main code to code that's copied
            # elsewhere to run)
            other_binary_addr, _ = movemanager.r2b(runtime_addr)
            if other_binary_addr is not None and (binary_addr is None or memorymanager.is_data_loaded_at_binary_addr(other_binary_addr, 1)):
                binary_addr = other_binary_addr
            if binary_addr is None:
                return []
        return [binary_addr]

    # What's known about the registers and flags (see cpuz80state.py)
    CpuState = cpuz80state.CpuState

    class Opcode:
        """An opcode, with its prefix (if any): 'key' is its bytes, without
        any displacement or immediate value (see opcode_specs()), and 'spec'
        says what it is (a Spec), from which it keeps the 'mnemonic',
        'operands', 'kind', 'cycles' and 'undocumented'. 'operand_length' is
        the number of bytes after the first, including any prefix's second
        byte, displacement or immediate value.

        One Opcode is shared by every instruction with those bytes, and
        reads the rest of the instruction from memory by its binary address.
        It's also the instruction's classification (see classification.py),
        as code."""

        def __init__(self, key, spec):
            self.key = key
            self.mnemonic = spec.mnemonic
            self.operands = spec.operands
            self.kind = spec.kind
            self.cycles = spec.cycles
            self.undocumented = spec.undocumented
            self.operand_length = spec.length - 1

        def length(self):
            """The instruction's length in bytes, including any prefix."""
            return 1 + self.operand_length

        def is_code(self, binary_addr):
            """True: an instruction is code (unlike a data classification)."""
            return True

        def indent(self, binary_addr):
            """Indent the instruction at binary_addr one more level (for a
            loop, with config.set_indent_loops(True))."""
            session.current().cpu.indent_level_dict[binary_addr] += 1

        def update_cpu_state(self, binary_addr, state):
            """Update 'state' (a CpuState) for this instruction at
            binary_addr, with cpuz80state.update_state(). The runtime
            address of the next instruction is passed too, since a jump to
            it says nothing about its condition."""
            # Nothing is known after an instruction the code can't continue
            # from (e.g. JP), or where code can come from elsewhere (at a
            # label)
            runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
            if state.block_end or (runtime_addr is not None and runtime_addr in session.current().labels.labels):
                state.clear()
            memory_binary = session.current().memory.binary
            if len(self.key) == 3:
                operands = [memory_binary[binary_addr + 2]]         # (DD CB d op: the displacement)
            else:
                operands = [memory_binary[binary_addr + i] for i in range(len(self.key), self.length())]
            next_addr = None if runtime_addr is None else (runtime_addr + self.length()) & 0xffff
            cpuz80state.update_state(state, self.key, operands, next_addr)

        def cycles_description(self, binary_addr):
            """The cycles the instruction takes, as shown with
            config.set_show_cycles(True), e.g. "7", or "7/12" for a
            conditional jump (not taken, or taken)."""
            return self.cycles

        def is_block_end(self):
            """True if the code can't continue to the next instruction: JP,
            JR, RET, RETI, RETN and JP (HL). (Not a conditional jump or
            return, a call or RST.) It ends a block, which gets a blank line
            after it unless config.set_blank_line_at_block_end(False)."""
            return self.kind in (FLOW_JP, FLOW_JR, FLOW_RET, FLOW_JP_IND)

        def part(self, cls):
            """The first operand part of class 'cls', or None."""
            return next((x for x in self.operands if isinstance(x, cls)), None)

        def target(self, binary_addr):
            """The runtime address a jump, call or RST goes to: for RST, the
            address in its opcode (bits 5-3, times 8); for a relative jump,
            the address after the instruction plus the offset (wrapping
            round at 16 bits); otherwise the 16 bit operand."""
            if self.kind == FLOW_RST:
                return RuntimeAddr(session.current().memory.binary[binary_addr] & 0x38)
            rel = self.part(Rel)
            if rel is not None:
                offset = _signed(session.current().memory.binary[binary_addr + rel.offset])
                return RuntimeAddr((movemanager.b2r(binary_addr) + self.length() + offset) & 0xffff)
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + self.part(Target).offset))

        def is_call(self):
            """True for CALL (conditional or not) and RST."""
            return self.kind in (FLOW_CALL, FLOW_RST)

        def update_references(self, binary_loc):
            """Record the references to labels that the instruction at
            binary_loc makes: to a jump or call's target, to the code an RST
            calls (if it's loaded), and to an address in brackets (e.g. 'ld
            a,(nn)'). An immediate value isn't taken to be an address, so
            it isn't a reference."""
            binary_addr = binary_loc.binary_addr
            labels = session.current().labels.labels
            if self.part(Target) is not None or self.part(Rel) is not None:
                labels[self.target(binary_addr)].add_reference(binary_loc)
            if self.kind == FLOW_RST:
                # (So that the code it calls gets a label, if it's loaded,
                # although the operand is a number)
                target = self.target(binary_addr)
                target_binary_addr = movemanager.r2b(target)[0]
                if target_binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(target_binary_addr, 1):
                    labels[target].add_reference(binary_loc)
            addr = self.part(Addr)
            if addr is not None:
                labels[RuntimeAddr(memorymanager.get_u16_binary(binary_addr + addr.offset))].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            """The binary addresses to trace next: the next instruction (or
            None, if the code doesn't continue to it), then any other (a
            jump's target, or the subroutine a call or RST calls). A jump's
            target is looked for in its own move first, except for JP (see
            cpu.Cpu.jump_target()).

            A call or RST returns to the next instruction, unless a
            subroutine hook (see CpuZ80.hook_subroutine()) gives another
            runtime address, e.g. after data that follows the call, or None
            if it doesn't return. The code an RST calls is only traced if
            it's loaded (it's then named, e.g. rst_08: see
            CpuZ80.label_maker())."""
            binary_addr = binary_loc.binary_addr
            next_addr = binary_addr + self.length()
            cpu = session.current().cpu
            if self.kind == FLOW_NEXT:
                return [next_addr]
            if self.kind in (FLOW_RET, FLOW_JP_IND):
                return [None]
            target = self.target(binary_addr)
            if self.kind == FLOW_JP:
                return [None] + cpu.jump_target(target, binary_loc)
            if self.kind == FLOW_JR:
                return [None] + cpu.jump_target(target, binary_loc, prefer_own_move=True)
            if self.kind in (FLOW_JP_CC, FLOW_JR_CC):
                return [next_addr] + cpu.jump_target(target, binary_loc, prefer_own_move=True)

            # A call or RST: a hook can say where it returns to (e.g. after
            # data following the call), or None if it doesn't
            def simple_call_hook(target_runtime_addr, caller_runtime_addr):
                """The default hook: the call returns to the next
                instruction."""
                return caller_runtime_addr + self.length()

            # (The hook is called with the call's move active, so that the
            # addresses it uses, e.g. with entry(), are looked for there)
            call_hook = cpu.subroutine_hooks.get(target, simple_call_hook)
            caller_runtime_addr = movemanager.b2r(binary_addr)
            with session.current().moves.move_id_for_binary_addr[binary_addr]:
                return_runtime_addr = call_hook(target, caller_runtime_addr)
            if return_runtime_addr is not None:
                return_runtime_addr = RuntimeAddr(return_runtime_addr)
                if return_runtime_addr == caller_runtime_addr + self.length():
                    result = [next_addr]
                else:
                    result = cpu.get_target_binary_addr_preferring_given_move_id(return_runtime_addr, binary_loc.move_id)
            else:
                result = [None]

            if self.kind == FLOW_RST:
                # (Only traced if it's loaded, since its operand isn't a label)
                target_binary_addr = movemanager.r2b(target)[0]
                if target_binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(target_binary_addr, 1):
                    return result
                cpu.rst_targets.add(target)
                return result + [target_binary_addr]
            return result + cpu.jump_target(target, binary_loc)

        def _part_text(self, binary_addr, part, in_context=True):
            """The text of an operand part (e.g. a label or number), as a
            label, constant or expression (see classification.py). Unless
            'in_context' is False (for the JSON), a value that isn't in
            brackets (an immediate value, or a jump or call's target) is
            rendered as an operand (expression.OPERAND), since z88dk-z80asm
            takes an operand that starts with a bracket to be in brackets,
            i.e. indirect (see Z88DK.expression_in_context())."""
            addr = binary_addr + part.offset
            expressions = session.current().classifications.expressions
            def operand(value):
                """The value, rendered as an operand (unless not
                'in_context')."""
                return expression.in_context(value, expression.OPERAND) if in_context else value
            if isinstance(part, Imm8):
                return operand(classification.get_constant8(addr))
            if isinstance(part, Imm16):
                return operand(classification.get_constant16(addr))
            if isinstance(part, Port):
                return classification.get_constant8(addr)
            if isinstance(part, Addr):
                return classification.get_address16(addr)
            if isinstance(part, Target):
                return operand(classification.get_address16(addr))
            if isinstance(part, Rel):
                # (The target's label: an expression for the offset isn't
                # used)
                label = disassembly.get_label(self.target(binary_addr), binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
                runtime_addr = movemanager.b2r(binary_addr)
                unwrapped = runtime_addr + self.length() + _signed(session.current().memory.binary[addr])
                if not 0 <= unwrapped < 0x10000:
                    # (The target wraps round the top or bottom of memory)
                    label = config.get_assembler().wrapped_branch_operand(label, unwrapped - runtime_addr)
                return label
            # An index register and its displacement, e.g. 'ix+2' or 'ix-3',
            # or 'ix+' and the displacement's expression
            assert isinstance(part, Index)
            displacement = self._displacement(addr)
            if addr in expressions:
                return utils.LazyString("%s+%s", utils.force_case(part.register), displacement)
            return utils.force_case(part.register) + ("" if displacement.startswith("-") else "+") + displacement

        def _displacement(self, addr):
            """The text of an index register's displacement (at addr): a
            signed number, or its expression."""
            value = _signed(session.current().memory.binary[addr])
            if addr in session.current().classifications.expressions:
                return classification.get_expression(addr, value)
            return str(value)

        def operand_part_text(self, binary_addr, part_addr):
            """The text of the operand part whose bytes start at part_addr,
            for the JSON (see jsonoutput.py): not rendered as an operand,
            and for an index register just the displacement."""
            part = next(x for x in self.operands if isinstance(x, Part) and binary_addr + x.offset == part_addr)
            if isinstance(part, Index):
                return self._displacement(part_addr)
            return self._part_text(binary_addr, part, in_context=False)

        def operand(self, binary_addr):
            """The operand, as a LazyString (or None if there isn't one): its
            text, in the output's case, with the text of each Part in its
            place. (A LazyString, since the labels are only named once
            tracing is done.)"""
            if not self.operands:
                return None
            fmt = ""
            args = []
            for part in self.operands:
                if isinstance(part, str):
                    fmt += utils.force_case(part).replace("%", "%%")
                else:
                    fmt += "%s"
                    args.append(self._part_text(binary_addr, part))
            return utils.LazyString(fmt, *args)

        def instruction(self, binary_addr):
            """The instruction (see output.Instruction). An undocumented
            opcode that the assembler doesn't accept (see
            Assembler.undocumented_z80_accepted()) is written as data bytes,
            with the instruction in a comment."""
            cpu = session.current().cpu
            if self.kind == FLOW_RST and cpu.trace_done and self.target(binary_addr) in cpu.rst_targets:
                # The code it calls gets a label (e.g. rst_08), although the
                # operand is a number: naming the label here means it's
                # output. (Not while tracing, for an overlapping
                # instruction's comment, which is formatted later.)
                str(disassembly.get_label(self.target(binary_addr), binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE))
            instruction = output.Instruction(self.mnemonic, self.operand(binary_addr))
            if self.undocumented is not None:
                kinds = self.undocumented if isinstance(self.undocumented, tuple) else (self.undocumented,)
                if not all(config.get_assembler().undocumented_z80_accepted(kind) for kind in kinds):
                    # Written as data bytes, with the instruction in a comment
                    instruction.form = output.Instruction.UNDOCUMENTED
                    instruction.data_items = self.data_items(binary_addr)
                    if self.undocumented == IGNORED_PREFIX:
                        instruction.comment_text = "prefix with no effect"
            return instruction

        def data_items(self, binary_addr):
            """The instruction's bytes, as data items (a label or expression
            where an operand has one), for an undocumented opcode written as
            data: the prefix and opcode bytes in hex, a 16 bit operand as
            the low and high bytes of its label, constant or expression, an
            8 bit one as a constant or expression, and a displacement as a
            signed number or its expression."""
            import maker
            memory_binary = session.current().memory.binary
            assembler = config.get_assembler()
            parts = {part.offset: part for part in self.operands if isinstance(part, Part)}
            result = []
            offset = 0
            while offset < self.length():
                part = parts.get(offset)
                addr = binary_addr + offset
                if isinstance(part, (Addr, Imm16, Target)):
                    value = classification.get_address16(addr) if isinstance(part, (Addr, Target)) else classification.get_constant16(addr)
                    result += [maker.make_lo(value), maker.make_hi(value)]
                    offset += 2
                    continue
                if isinstance(part, (Imm8, Port)):
                    result.append(classification.get_constant8(addr))
                elif isinstance(part, Index):
                    result.append(self._displacement(addr))
                else:
                    result.append(assembler.hex2(memory_binary[addr]))
                offset += 1
            return result

        def as_lines(self, binary_loc, annotations):
            """The output for the instruction at binary_loc, as a list of
            line objects (see output.py)."""
            binary_addr = binary_loc.binary_addr
            result = [self.instruction(binary_addr).placed(binary_loc, self.length(), session.current().cpu.indent_level_dict.get(binary_addr, 0),
                                                           self.cycles_description(binary_addr), annotations)]
            if self.is_block_end() and config.get_blank_line_at_block_end():
                result.append(output.Blank())
            return result

        def json_operand(self, binary_addr):
            """The operand for the JSON: (mode, value, bits, target, the
            binary address of the operand's bytes), with None for those
            there aren't. If there's more than one part (e.g. 'ld
            (ix+d),n'), the first in the order below is given (there, the
            displacement). An RST's target is the address it calls."""
            for cls, mode, bits in ((Rel, "relative", 8), (Target, "address", 16), (Addr, "address", 16),
                                    (Imm16, "immediate16", 16), (Index, "indexed", 8), (Imm8, "immediate", 8), (Port, "port", 8)):
                part = self.part(cls)
                if part is None:
                    continue
                addr = binary_addr + part.offset
                if cls is Rel:
                    target = int(self.target(binary_addr))
                    return mode, target, bits, target, addr
                value = memorymanager.get_u16_binary(addr) if bits == 16 else session.current().memory.binary[addr]
                if cls is Index:
                    value = _signed(value)
                return mode, value, bits, value if cls is Target else None, addr
            if self.kind == FLOW_RST:
                target = int(self.target(binary_addr))
                return "implied", None, None, target, None
            return "implied", None, None, None, None

    def is_subroutine_call(self, binary_addr):
        """Whether the instruction at binary_addr is a CALL (conditional or
        not) or RST, for naming the label of the code it calls 'sub_...'
        (see disassembly.suggest_label_name())."""
        c = classification.get_classification(binary_addr)
        return isinstance(c, self.Opcode) and c.is_call()

    def is_branch_to(self, binary_addr, target_runtime_addr):
        """Whether the instruction at binary_addr is a jump (JP, JR or DJNZ,
        conditional or not) to target_runtime_addr, for naming a loop's
        label 'loop_...' (see disassembly.suggest_label_name())."""
        c = classification.get_classification(binary_addr)
        if isinstance(c, self.Opcode) and c.kind in (FLOW_JP, FLOW_JP_CC, FLOW_JR, FLOW_JR_CC):
            return c.target(binary_addr) == target_runtime_addr
        return False

    def label_maker(self, lmd):
        """Name an auto-generated label for code that an RST calls rst_NN
        (e.g. rst_08), and one on a RET instruction ($C9) return_1,
        return_2 etc. (numbered in the order they're first named), unless
        config.set_label_return_instructions_numerically(False). 'lmd' is
        the label's LabelMakingData, with the name chosen so far: this is
        called for each label as it's named, after the default name is
        chosen (see disassembly._label_maker())."""
        # Label code reached by RST 'rst_NN', and RET instructions return_1,
        # return_2 etc.
        if not lmd.is_autogenerated:
            return
        if lmd.defined_as_runtime_addr in self.rst_targets:
            lmd.name = utils.force_case("rst_%02x" % lmd.defined_as_runtime_addr)
            return
        memory_binary = session.current().memory.binary
        if config.get_label_return_instructions_numerically():
            defined_at_binary_addr, _ = movemanager.r2b(lmd.defined_as_runtime_addr, lmd.defined_in_move_id)
            c = classification.get_classification(defined_at_binary_addr)
            if isinstance(c, self.Opcode) and memory_binary[defined_at_binary_addr] == OPCODE_RET:
                if not defined_at_binary_addr in self.return_array:
                    self.return_index += 1
                    self.return_array[defined_at_binary_addr] = self.return_index
                lmd.name = "return_{0}".format(self.return_array[defined_at_binary_addr])
