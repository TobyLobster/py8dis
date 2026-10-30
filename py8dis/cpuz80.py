"""
The Z80 CPU.

The opcode table is made from the fields of each opcode (as described in
"Decoding Z80 opcodes": x = bits 7-6, y = bits 5-3, z = bits 2-0, p = bits
5-4, q = bit 3), for each prefix: none, CB, ED, DD and FD (IX and IY in place
of HL), and DD CB and FD CB (the CB instructions on (IX+d) and (IY+d)).

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

# How control continues after an instruction (Opcode.kind)
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
    'offset' from its first byte."""
    def __init__(self, offset):
        self.offset = offset

class Imm8(Part):       # an 8 bit immediate value, e.g. 'ld a,n'
    size = 1
class Imm16(Part):      # a 16 bit immediate value, e.g. 'ld hl,nn'
    size = 2
class Addr(Part):       # a 16 bit address in brackets, e.g. 'ld a,(nn)'
    size = 2
class Target(Part):     # a 16 bit jump or call address, e.g. 'jp nn'
    size = 2
class Rel(Part):        # a relative jump, e.g. 'jr e'
    size = 1
class Port(Part):       # an I/O port in brackets, e.g. 'in a,(n)'
    size = 1
class Index(Part):      # an indexed address, e.g. '(ix+d)'
    size = 1
    def __init__(self, offset, register):
        super().__init__(offset)
        self.register = register

def _signed(n):
    return n - 0x100 if n >= 0x80 else n

class Spec:
    """An opcode, as made by the decoding functions below."""
    def __init__(self, length, text, operands=(), kind=FLOW_NEXT, cycles="", undocumented=None):
        self.length = length
        words = text.split(" ", 1)
        self.mnemonic = words[0]
        self.operands = ([words[1]] if len(words) > 1 else []) + list(operands)
        self.kind = kind
        self.cycles = cycles
        self.undocumented = undocumented

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
    after DD, or "iy" after FD) in place of HL. With an index register,
    returns None if the opcode doesn't use HL, H, L or (HL), since the prefix
    then has no effect."""

    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    p, q = y >> 1, y & 1
    o = 1 if index else 0               # the offset of the opcode byte

    def plain(text, length=1, cycles=4, kind=FLOW_NEXT, operands=()):
        if index:
            return None
        return Spec(length, text, operands, kind, str(cycles))

    def with_hl(text, length, cycles, index_cycles, operands=(), kind=FLOW_NEXT):
        """An instruction that uses HL (as written in 'text'), with IX or IY
        in its place after a prefix."""
        if index:
            operands = [x.replace("hl", index) if isinstance(x, str) else x for x in operands]
            return Spec(o + length, text.replace("hl", index), operands, kind, str(index_cycles))
        return Spec(length, text, operands, kind, str(cycles))

    def reg8(i):
        """Register i, with IXH/IXL (or IYH/IYL) for H/L after a prefix."""
        if index and i in (4, 5):
            return index + "hl"[i - 4]
        return R[i]

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

    if x == 2:
        if z == 6:
            if index:
                return Spec(3, ALU[y] + "(", [Index(2, index), ")"], cycles="19")
            return Spec(1, ALU[y] + "(hl)", cycles="7")
        if index and z in (4, 5):
            return Spec(2, ALU[y] + reg8(z), cycles="8", undocumented=INDEX_HALVES)
        return plain(ALU[y] + R[z])

    # x == 3
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
    """The opcode CB op."""
    x, y, z = op >> 6, (op >> 3) & 7, op & 7
    hl = z == 6
    if x == 0:
        return Spec(2, ROT[y] + " " + R[z], cycles="15" if hl else "8", undocumented=SLL if y == 6 else None)
    mnemonic = ("bit", "res", "set")[x - 1]
    return Spec(2, "%s %d,%s" % (mnemonic, y, R[z]), cycles=("12" if x == 1 else "15") if hl else "8")


def _index_cb(op, index):
    """The opcode DD CB d op (index "ix") or FD CB d op ("iy")."""
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
    """The opcode ED op."""
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
    e.g. (0xdd, 0xcb, 0x06) for DD CB d 06) to Spec."""
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
    """The Z80 CPU"""

    def __init__(self):
        super().__init__()

        # For labelling ret instructions numerically
        self.return_index = 0
        self.return_array = {}

        # indent_level_dict has binary addresses as the keys, and indent amounts as the values.
        self.indent_level_dict = collections.defaultdict(int)

        # The opcodes, by prefix: self.opcodes has the unprefixed ones (the
        # prefixes aren't in it)
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

    def opcode_at(self, binary_addr):
        """The opcode at binary_addr (an Opcode), or None if there isn't one
        (or its bytes aren't all there)."""
        memory_binary = session.current().memory.binary
        def byte(offset):
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
        runtime_addr = RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        self.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, name, explicit=True)
        self.subroutine_hooks[runtime_addr] = hook

    def get_target_binary_addr_preferring_given_move_id(self, runtime_addr, specific_move_id):
        """Given an instruction's operand address (a runtime address), find
        its most likely binary address, for the current set of active move
        ids."""
        binary_addr, _ = movemanager.r2b(runtime_addr, specific_move_id)
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr, 1):
            # (e.g. a jump from the main code to code that's copied
            # elsewhere to run)
            other_binary_addr, _ = movemanager.r2b(runtime_addr)
            if other_binary_addr is not None and (binary_addr is None or memorymanager.is_data_loaded_at_binary_addr(other_binary_addr, 1)):
                binary_addr = other_binary_addr
            assert binary_addr is not None
        return [binary_addr]

    # What's known about the registers and flags (see cpuz80state.py)
    CpuState = cpuz80state.CpuState

    class Opcode:
        """An opcode, with its prefix (if any): 'key' is its bytes, without
        any displacement or immediate value (see opcode_specs()), and 'spec'
        says what it is (a Spec)."""

        def __init__(self, key, spec):
            self.key = key
            self.mnemonic = spec.mnemonic
            self.operands = spec.operands
            self.kind = spec.kind
            self.cycles = spec.cycles
            self.undocumented = spec.undocumented
            self.operand_length = spec.length - 1

        def length(self):
            return 1 + self.operand_length

        def is_code(self, binary_addr):
            return True

        def indent(self, binary_addr):
            session.current().cpu.indent_level_dict[binary_addr] += 1

        def update_cpu_state(self, binary_addr, state):
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
            return self.kind in (FLOW_JP, FLOW_JR, FLOW_RET, FLOW_JP_IND)

        def part(self, cls):
            """The first operand part of class 'cls', or None."""
            return next((x for x in self.operands if isinstance(x, cls)), None)

        def target(self, binary_addr):
            """The runtime address a jump, call or RST goes to."""
            if self.kind == FLOW_RST:
                return RuntimeAddr(session.current().memory.binary[binary_addr] & 0x38)
            rel = self.part(Rel)
            if rel is not None:
                offset = _signed(session.current().memory.binary[binary_addr + rel.offset])
                return RuntimeAddr((movemanager.b2r(binary_addr) + self.length() + offset) & 0xffff)
            return RuntimeAddr(memorymanager.get_u16_binary(binary_addr + self.part(Target).offset))

        def is_call(self):
            return self.kind in (FLOW_CALL, FLOW_RST)

        def update_references(self, binary_loc):
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
            None), then any other."""
            binary_addr = binary_loc.binary_addr
            next_addr = binary_addr + self.length()
            cpu = session.current().cpu
            if self.kind == FLOW_NEXT:
                return [next_addr]
            if self.kind in (FLOW_RET, FLOW_JP_IND):
                return [None]
            target = self.target(binary_addr)
            if self.kind == FLOW_JP:
                return [None, movemanager.r2b(target)[0]]
            if self.kind == FLOW_JR:
                return [None] + cpu.get_target_binary_addr_preferring_given_move_id(target, binary_loc.move_id)
            if self.kind in (FLOW_JP_CC, FLOW_JR_CC):
                return [next_addr] + cpu.get_target_binary_addr_preferring_given_move_id(target, binary_loc.move_id)

            # A call or RST: a hook can say where it returns to (e.g. after
            # data following the call), or None if it doesn't
            def simple_call_hook(target_runtime_addr, caller_runtime_addr):
                return caller_runtime_addr + self.length()

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

            target_binary_addr = movemanager.r2b(target)[0]
            if self.kind == FLOW_RST:
                # (Only traced if it's loaded, since its operand isn't a label)
                if target_binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(target_binary_addr, 1):
                    return result
                cpu.rst_targets.add(target)
            return result + [target_binary_addr]

        def _part_text(self, binary_addr, part, in_context=True):
            """The text of an operand part (e.g. a label or number). Unless
            'in_context' is False (for the JSON), a value that isn't in
            brackets is as an operand, which some assemblers take to be in
            brackets if it starts with one."""
            addr = binary_addr + part.offset
            expressions = session.current().classifications.expressions
            def operand(value):
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
                label = disassembly.get_label(self.target(binary_addr), binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
                runtime_addr = movemanager.b2r(binary_addr)
                unwrapped = runtime_addr + self.length() + _signed(session.current().memory.binary[addr])
                if not 0 <= unwrapped < 0x10000:
                    # (The target wraps round the top or bottom of memory)
                    label = config.get_assembler().wrapped_branch_operand(label, unwrapped - runtime_addr)
                return label
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
            """The text of the operand part whose bytes start at part_addr."""
            part = next(x for x in self.operands if isinstance(x, Part) and binary_addr + x.offset == part_addr)
            if isinstance(part, Index):
                return self._displacement(part_addr)
            return self._part_text(binary_addr, part, in_context=False)

        def operand(self, binary_addr):
            """The operand, as a LazyString (or None if there isn't one)."""
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
            """The instruction (see output.Instruction)."""
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
            where an operand has one)."""
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
            there aren't."""
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
        c = classification.get_classification(binary_addr)
        return isinstance(c, self.Opcode) and c.is_call()

    def is_branch_to(self, binary_addr, target_runtime_addr):
        c = classification.get_classification(binary_addr)
        if isinstance(c, self.Opcode) and c.kind in (FLOW_JP, FLOW_JP_CC, FLOW_JR, FLOW_JR_CC):
            return c.target(binary_addr) == target_runtime_addr
        return False

    def label_maker(self, lmd):
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
