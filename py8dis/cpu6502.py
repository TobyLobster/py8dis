"""
The 6502 CPU

Cpu6502 decodes, traces and follows the CPU state of 6502 code, and analyses
it once it's traced, to add comments and names. The 6510 (with the 6502's
undocumented opcodes, cpu6510.py) and the 65C02 (cpu65C02.py) are derived
from it. (The base class, cpu.Cpu, has the parts that every CPU shares.)

Opcodes. Cpu6502.opcodes maps each documented opcode to an opcode object,
an instance of one of the Opcode classes nested in Cpu6502. Each is made
from a template such as "LDA (zp),Y" (parsed by
parse_instruction_template()), how the instruction affects A, X and Y, its
cycle count, and a function that updates the CPU state for it. The class
says how the instruction is traced (disassemble(): the addresses to trace
next), which address it refers to (update_references()), how it's written
(instruction()) and how it changes the CPU state (update_cpu_state()).

Tracing (see Cpu.trace()). After most instructions the next one is traced.
A conditional branch is traced both ways, and JMP at its target only.
Tracing stops after RTS, RTI and BRK, and after JMP (addr), whose target
isn't known until it runs. A JSR's target is traced, and tracing carries on
after the JSR, unless a subroutine hook (see hook_subroutine()) says the
subroutine returns somewhere else (e.g. after a string that follows the
JSR) or doesn't return at all. Snippets (snippets6502.py) and effect
patterns (effectpattern.py) recognise common pieces of code, and can add
entry points.

The CPU state. Once the code is traced, Cpu.calculate_cpu_states() goes
through it working out what's known after each instruction: a CpuState,
which holds what's known about A, X and Y (RegState: the value, and which
instruction last loaded, changed or used the register) and the flags. It
holds two versions of this (CpuStateDisposition): the pessimistic one is
what's known for certain, which is forgotten at each label (code can come
there from elsewhere); the optimistic one takes the code to have run
straight through from the instruction before, even past a label. E.g. 'LDA
#5' makes A 5; a conditional branch is taken not to have been taken, so its
flag is known after it (and after BNE, the register that set Z: see
z_source()); and nothing is known after a JSR, JMP or RTS. docs/cpus.md
describes this for users.

Analysis. The functions in code_analysis_fns use the CPU states to comment
calls to subroutines described with subroutine() (find_subroutine_calls()),
name constants given with substitute_constants() (substitute_constants(),
SubConst), comment known register values and branches that are always
taken (show_register_knowledge()), and comment redundant instructions
(find_redundant_instructions()). straight_runs() and memory_writes() say
what straight runs of code write to memory, for effect patterns and the
machine modules (e.g. acorn.py and commodore.py).
"""

import classification
import collections
import config
import disassembly
import effectpattern
import labelmanager
import mainformatter
import output
import memorymanager
import movemanager
import session
import re
import cpu
import utils
import textencoding
from align import Align
from binaryaddrtype import BinaryAddrType
from memorymanager import BinaryAddr
from snippethelper import *


# Opcodes that the code below looks for (e.g. the ADC and SBC ones, to
# comment them when the carry flag is known: see show_register_knowledge())
OPCODE_JSR = 0x20
OPCODE_JMP = 0x4c
OPCODE_RTS = 0x60

OPCODE_ADC_INDEXED_INDIRECT  = 0x61
OPCODE_ADC_ZERO_PAGE         = 0x65
OPCODE_ADC_IMMEDIATE         = 0x69
OPCODE_ADC_ABSOLUTE          = 0x6d
OPCODE_ADC_INDIRECT_INDEXED  = 0x71
OPCODE_ADC_ZERO_PAGE_COMMA_X = 0x75
OPCODE_ADC_ABSOLUTE_COMMA_Y  = 0x79
OPCODE_ADC_ABSOLUTE_COMMA_X  = 0x7d

OPCODE_SBC_INDEXED_INDIRECT  = 0xe1
OPCODE_SBC_ZERO_PAGE         = 0xe5
OPCODE_SBC_IMMEDIATE         = 0xe9
OPCODE_SBC_ABSOLUTE          = 0xed
OPCODE_SBC_INDIRECT_INDEXED  = 0xf1
OPCODE_SBC_ZERO_PAGE_COMMA_X = 0xf5
OPCODE_SBC_ABSOLUTE_COMMA_Y  = 0xf9
OPCODE_SBC_ABSOLUTE_COMMA_X  = 0xfd

class SubConst:
    """Data about a constant substitution.

    These are stored in substitute_constant_list (in the session's trace
    state: see trace.py), by substitute_constants() and machine modules
    such as acorn.py and commodore.py. Cpu6502.substitute_constants() uses
    them."""

    def __init__(self, instruction, reg, constants_dict, define_constant, condition=None):
        """'instruction' is the instruction to look for, with its operand,
        e.g. 'sta sprite_number' or 'jsr $ffee' (the operand is a label's
        name or a hex address). 'reg' is the register ('a', 'x' or 'y')
        whose immediate load before it is to be named, from constants_dict
        ({value: name or expression}). If define_constant, the names used
        are defined as constants.

        condition, if given, is called with the instruction's binary
        address, and the substitution is made only if it returns True."""
        mnemonic, operand, operand_length, prefix, suffix, addr_modes = Cpu6502.parse_instruction(instruction)
        self.condition      = condition
        self.mnemonic       = mnemonic
        self.addr_modes     = addr_modes        # There can be two possible addressing modes, a zp and addr version
        self.operand        = operand           # This is a label
        self._opcode        = None              # not set yet
        self.reg            = reg
        self.constants_dict = constants_dict
        self.define_constant = define_constant

    def get_opcode(self, opcodes):
        """The opcode of the instruction, found in 'opcodes' (the CPU's
        table) from its mnemonic and addressing mode, or None if there isn't
        one. Where the operand could be zero page or absolute (e.g. 'sta
        addr'), its value decides. (Worked out when it's first asked for,
        after tracing, and kept. This also sets 'addr_mode'.)"""
        # If already calculated, return it
        if self._opcode is not None:
            return self._opcode

        # (Only an operand that could be either needs its value. An
        # instruction may have no operand at all, e.g. 'rts'.)
        if len(self.addr_modes) > 1 and self.get_operand_value() >= 0x100:
            self.addr_mode = self.addr_modes[1]
        else:
            self.addr_mode = self.addr_modes[0]

        # Get opcode from mnemonic and addr_mode
        for opcode_key in opcodes:
            if opcodes[opcode_key].mnemonic.lower() == self.mnemonic.lower():
                if opcodes[opcode_key].addr_mode == self.addr_mode:
                    self._opcode = opcode_key
                    return opcode_key

    def get_operand_value(self):
        """The operand's address: the address of the label or optional
        label with the name given, or the hex address given ('$ffee' or
        '&ffee', or 'ffee' if no label has that name)."""
        # A hex address (no name starts with '&' or '$', so this is what the
        # lookups below would give, without searching the labels)
        if self.operand[0] in "&$":
            return int(self.operand[1:], 16)

        # Look up label
        result = labelmanager.addr(self.operand)
        if result is not None:
            return result

        for addr in session.current().disassembly.optional_labels:
            if session.current().disassembly.optional_labels[addr].name == self.operand:
                return addr

        # Assume hex of some kind. Remove common prefixes.
        result = self.operand
        if result[0] in "&$":
            result = result[1:]
        return int(result, 16)


class MemoryWrite:
    """A write to memory by an instruction (see Cpu6502.memory_writes()).

    binary_addr is the instruction's binary address. target is the address
    written (a runtime address), or None if it isn't known (e.g. an indexed
    store), in which case any memory may have changed. value is the value
    written, if it's known (e.g. 'sta' of a known A). reg is the register
    stored ('a', 'x' or 'y'), or None (e.g. STZ, a read-modify-write).
    value_operand is the binary address of the immediate operand the value
    was loaded from (e.g. the 'nn' of 'lda #nn'), if the value is a
    register's that was loaded that way (and not changed since), or None.
    read_modify_write is True for e.g. INC or ASL, which read the memory as
    well."""

    __slots__ = ("binary_addr", "target", "value", "reg", "value_operand", "read_modify_write")

    def __init__(self, binary_addr, target, value=None, reg=None, value_operand=None, read_modify_write=False):
        self.binary_addr = binary_addr
        self.target = target
        self.value = value
        self.reg = reg
        self.value_operand = value_operand
        self.read_modify_write = read_modify_write

    def __repr__(self):
        return "MemoryWrite({0}, {1}, {2}, {3}, {4}, {5})".format(
            hex(self.binary_addr), None if self.target is None else hex(self.target), self.value, self.reg, self.value_operand, self.read_modify_write)


class RegState:
    """What's known about one register (A, X or Y) at a point in the code:
    its value, and the binary addresses of the instructions that last
    loaded, changed and used it (see the attributes in clear()). The
    addresses are what the analysis comments or names, e.g. the 'ldx #nn'
    that sets X up for a call to a subroutine."""

    def __init__(self):
        """Nothing is known to start with."""
        self.clear()

    def clear(self):
        """Forget everything about the register."""
        self.value              = None      # Current value, if known
        self.previous_load_imm  = None      # The address of the previous load immediate instruction if no adjustments made since
        self.previous_load      = None      # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
        self.previous_adjust    = None      # The address of the previous load or adjust instruction if present
        self.previous_use       = None      # The address of the previous 'read only use of a register' instruction if present

    def copy(self):
        """A fast copy (all the attributes are immutable values)."""
        result = RegState.__new__(RegState)
        result.__dict__.update(self.__dict__)
        return result

    def get_previous_load_imm_operand(self):
        """The binary address of the immediate operand that the register's
        value was loaded from (e.g. the 'nn' of 'lda #nn', perhaps followed
        by 'tax' for X), if it hasn't changed since, otherwise None. Giving
        that operand an expression names the value."""
        if self.previous_load_imm is not None:
            return self.previous_load_imm+1
        return None

    def __repr__(self):
        """The register's value as text (for __str__())."""
        return "value: {0}".format(self.value)

    def __str__(self):
        return self.__repr__()

class CpuStateDisposition:
    """One version of what's known about the CPU after an instruction
    (CpuState holds two: optimistic and pessimistic).

    Indexed by register or flag: 'a', 'x' and 'y' give a RegState; 'n',
    'v', 'd', 'i', 'z' and 'c' give the flag, True or False (or 1 or 0) if
    it's known, otherwise None. Z and C can also be 'pending' after a
    compare: unknown, but a branch on one of them that isn't taken says
    something about the other (see update_transfer()). Anything else
    counts 'pending' as unknown.

    The update_*() methods (and decrement() etc.) change it for what an
    instruction does to the flags and the registers' values; the
    Cpu6502.update_*() functions call them for both versions."""

    def __init__(self):
        """Nothing is known to start with."""
        self._d = {
            # For A/X/Y, value is RegState.
            "a": RegState(),
            "x": RegState(),
            "y": RegState(),
            # For flags, value is True/False if known.
            "n": None,
            "v": None,
            "d": None,
            "i": None,
            "z": None,
            "c": None,
        }

        # What the Z flag says about the registers, if anything: (registers,
        # value, binary address), meaning Z is set if and only if each of
        # the registers is that value, as worked out by the instruction at
        # that address (e.g. (('y',), 0, addr) after DEY, or (('a',), $7b,
        # addr) after CMP #$7b). So when a branch that isn't taken shows Z is
        # set, the registers' values are known. (See Cpu6502.z_source().)
        self.z_from = None

    def copy(self):
        """A fast copy (much faster than copy.deepcopy())."""
        result = CpuStateDisposition.__new__(CpuStateDisposition)
        result._d = {key: (value.copy() if isinstance(value, RegState) else value) for key, value in self._d.items()}
        result.z_from = self.z_from
        return result

    def clear(self):
        """Forget everything: no register or flag is known."""
        self._d["a"].clear()
        self._d["x"].clear()
        self._d["y"].clear()
        self._d["n"] = None
        self._d["v"] = None
        self._d["d"] = None
        self._d["i"] = None
        self._d["z"] = None
        self._d["c"] = None
        self.z_from = None

    def __getitem__(self, key):
        assert key in "axynvdizc"
        return self._d[key]

    def __setitem__(self, key, item):
        """Set a register (a RegState, or None for one with nothing known)
        or a flag (True, False, 0, 1, 'pending' or None)."""
        assert key in "axynvdizc"
        if key in "axy":
            if item is None:
                item = RegState()
            assert isinstance(item, RegState)
        else:
            assert item is None or item == 'pending' or utils.is_integer_type(item)
        self._d[key] = item

    def update_clear_nz(self, binary_addr):
        """N and Z become unknown."""
        self._d['n'] = None
        self._d['z'] = None

    def update_clear_nza(self, binary_addr):
        """N, Z and A's value become unknown."""
        self._d['n'] = None
        self._d['z'] = None
        self._d['a'].value = None

    def update_clear_nzc(self, binary_addr):
        """N, Z and C become unknown."""
        assert binary_addr is not None
        self._d['n'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_clear_nzca(self, binary_addr):
        """N, Z, C and A's value become unknown."""
        self._d['n'] = None
        self._d['z'] = None
        self._d['c'] = None
        self._d['a'].value = None

    def update_clear_nz_pending_c(self, binary_addr):
        """N becomes unknown, and Z and C 'pending' (for a compare)."""
        # This is used for comparison instructions.
        # Note c is set to 'pending' so that after "CMP blah:BNE addr" we can set C
        # Similarly z is set to 'pending' so that after "CMP blah:BCS addr" we can clear Z
        self._d['n'] = None
        self._d['z'] = "pending"
        self._d['c'] = "pending"

    def update_rora(self, binary_addr):
        """ROR A: if A and C are known, A, N, Z and C are worked out;
        otherwise they become unknown."""
        # Note carry may be 'pending' (after a compare), which counts as unknown here.
        if self._d['a'].value is not None and self._d['c'] in (True, False):
            # We know that state of A and carry, so we can calculate the new value of A
            oldv = self._d['a'].value
            newc = oldv & 1
            self._d['a'].value = oldv // 2
            if self._d['c']:
                self._d['a'].value += 0x80

            self._d['n'] = (self._d['a'].value & 0x80) == 0x80
            self._d['z'] = (self._d['a'].value == 0)
            self._d['c'] = newc
            return

        self._d['n'] = None
        self._d['z'] = None
        self._d['c'] = None
        self._d['a'].value = None

    def update_bit(self, binary_addr):
        """N, V and Z become unknown (BIT)."""
        assert binary_addr is not None
        self._d['n'] = None
        self._d['v'] = None
        self._d['z'] = None

    def update_adc_sbc(self, binary_addr):
        """A's value, N, V, Z and C become unknown (ADC, SBC)."""
        assert binary_addr is not None
        self._d['a'].value = None
        self._d['n'] = None
        self._d['v'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_all_flags(self, binary_addr):
        """All the flags become unknown (PLP)."""
        assert binary_addr is not None
        self._d['n'] = None
        self._d['v'] = None
        self._d['d'] = None
        self._d['i'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_AND_immediate(self, binary_addr):
        """AND #imm (the instruction at binary_addr): A, N and Z are worked
        out if A is known, and otherwise as far as the operand says (e.g.
        AND #0 makes A 0)."""
        memory_binary = session.current().memory.binary
        assert binary_addr is not None
        v = memory_binary[binary_addr+1]
        if self._d['a'].value is not None:
            # Value of A is known, so calculate new value of A
            v = self._d['a'].value & v
            self._d['a'].value = v

            # Update the flags based on new value of A
            self._d['n'] = ((v & 0x80) == 0x80)
            self._d['z'] = (v == 0)
        elif v == 0:
            # AND #0 sets the Z flag, and A=0
            self._d['a'].value = 0
            self._d['n'] = 0
            self._d['z'] = 1
        else:
            # A is unknown, so the result (and therefore Z) is unknown
            self._d['z'] = None

            # AND with value $01-$7f leaves the N flag clear, otherwise it is unknown
            self._d['n'] = 0 if v < 0x80 else None

    def update_ORA_immediate(self, binary_addr):
        """ORA #imm (the instruction at binary_addr): A, N and Z are worked
        out if A is known, and otherwise as far as the operand says (e.g.
        ORA #$ff makes A $ff)."""
        memory_binary = session.current().memory.binary
        assert binary_addr is not None
        v = memory_binary[binary_addr+1]
        if self._d['a'].value is not None:
            # Value of A is known, so calculate new value of A
            v = self._d['a'].value | v
            self._d['a'].value = v

            # Update the flags based on new value of A
            self._d['n'] = ((v & 0x80) == 0x80)
            self._d['z'] = (v == 0)
        elif v == 0xff:
            # ORA #$ff sets A=$ff
            self._d['a'].value = 0xff
            self._d['n'] = 1
            self._d['z'] = 0
        elif v > 0:
            # ORA with non-zero value means Z is clear
            self._d['z'] = 0

            # ORA with a value $80-$ff sets the N flag, otherwise it is unknown
            self._d['n'] = 1 if v >= 0x80 else None
        else:
            # ORA #0 leaves A unchanged (but unknown), so N and Z are unknown
            self._d['n'] = None
            self._d['z'] = None

    def decrement(self, addr, reg):
        """DEX, DEY (or the 65C02's DEC A) at addr: if the register is
        known, it's one less (wrapping round from 0 to $ff), with N and Z
        from it; otherwise N and Z become unknown."""
        v = self[reg].value
        if v is not None:
            v -= 1
            if v == -1:
                v = 0xff
            self[reg].value = v
            self['n'] = ((v & 0x80) == 0x80)
            self['z'] = (v == 0)

            # Now we have a new value for the register, the address where we previously
            # loaded the current value no longer valid
            self[reg].previous_load_imm = None
            self[reg].previous_load     = None
            self[reg].previous_adjust   = BinaryAddr(addr)
        else:
            self.update_clear_nz(addr)

    def increment(self, addr, reg):
        """INX, INY (or the 65C02's INC A) at addr, as decrement() but one
        more (wrapping round from $ff to 0)."""
        v = self[reg].value
        if v is not None:
            v += 1
            if v == 0x100:
                v = 0
            self[reg].value = v
            self['n'] = ((v & 0x80) == 0x80)
            self['z'] = (v == 0)

            self[reg].previous_load_imm    = None
            self[reg].previous_load        = None
            self[reg].previous_adjust      = BinaryAddr(addr)
        else:
            self.update_clear_nz(addr)

    def load_immediate(self, addr, reg, v):
        """LDA, LDX or LDY #v at addr: the register is v, with N and Z from
        it, and the instruction at addr is where it was loaded."""
        # (The instruction's address: get_previous_load_imm_operand() gives
        # its operand's)
        addr = BinaryAddr(addr)

        self[reg].value = v
        self['n'] = ((v & 0x80) == 0x80)
        self['z'] = (v == 0)
        self[reg].previous_load_imm = addr
        self[reg].previous_load     = addr
        self[reg].previous_adjust   = addr


    def transfer(self, addr, src_reg, dest_reg):
        """A transfer (TAX, TXA etc.) at addr: dest_reg gets src_reg's value
        (if known), with N and Z from it, and the instruction at addr is
        where it was loaded."""
        addr = BinaryAddr(addr)
        self[dest_reg].value = self[src_reg].value

        # If we have a load address, keep it. This allows
        # the code (e.g. from basic4) to understand X and Y form an
        # address <const> here:
        #
        #    lda #<const>
        #    tay
        #    ldx #<const>
        #    jsr OSWORD
        #
        self[dest_reg].previous_load_imm = self[src_reg].previous_load_imm
        self[dest_reg].previous_load = addr
        self[dest_reg].previous_adjust = addr

        v = self[dest_reg].value
        if v is not None:
            self['n'] = ((v & 0x80) == 0x80)
            self['z'] = (v == 0)
        else:
            self['n'] = None
            self['z'] = None

    def update_transfer(self, addr, flag, flag_state):
        """A conditional branch at addr on 'flag' that isn't taken: the flag
        is flag_state (if it wasn't known already). And what that says about
        the rest: after a compare, Z set means C is set, and C clear means Z
        is clear; and if Z is set, the registers whose result set it have
        the value that sets it (see z_from), and N is clear. (Called by the
        update functions that Cpu6502.make_branch() makes.)"""
        if self[flag] is None or self[flag] == 'pending':
            self[flag] = flag_state

        if flag == 'z' and flag_state == True and self['c'] == 'pending':
            # We have 'BNE addr' with c == 'pending' from a previous compare instruction
            self['c'] = True
        if flag == 'z' and flag_state == True and self.z_from is not None:
            # We have 'BNE addr' after an instruction whose result set Z, so
            # the result was 0: e.g. Y is 0 after 'DEY : BNE addr', and A is
            # $7b after 'CMP #$7b : BNE addr'. (N is clear, being bit 7 of
            # that result.)
            regs, value, z_addr = self.z_from
            for reg in regs:
                if self[reg].value is None:
                    # (No instruction set it to this value: it's only this
                    # value after the branch, so comments on its use, e.g.
                    # a VDU command, go where it's used)
                    self[reg].value = value
                    self[reg].previous_load_imm = None
                    self[reg].previous_load = None
                    self[reg].previous_adjust = None
            if self['n'] is None:
                self['n'] = False
        if flag == 'c' and flag_state == False and self['z'] == 'pending':
            # We have 'BCS addr' with z == 'pending' from a previous compare instruction
            self['z'] = False

    def show(self):
        """The state as text, e.g. 'A:05 X:-- Y:00 nvdIzc': '--' for a
        register that isn't known, and each flag upper case if it's set,
        lower case if it's clear, '-' if it isn't known, or '?' if it's
        'pending'."""
        s = ""
        def reg(r):
            v = self._d[r].value
            if v is None:
                return "--"
            return utils.plainhex2(v)
        s += "A:%s X:%s Y:%s" % (reg('a'), reg('x'), reg('y'))

        def flag(name):
            b = self._d[name]
            if b is None:
                return "-"
            if b == 'pending':
                return "?"
            return name.upper() if b else name.lower()
        s += " %s%s%s%s%s%s" % (flag('n'), flag('v'), flag('d'), flag('i'), flag('z'), flag('c'))
        return s

    def __repr__(self):
        """The state as text (see show())."""
        return self.show()
    def __str__(self):
        return self.__repr__()

def branch_target(binary_addr):
    """The target of the relative branch at binary_addr, without wrapping
    round the top or bottom of memory (so it can be below 0 or above $ffff)."""
    return movemanager.b2r(binary_addr) + 2 + utils.signed8(memorymanager.get_u8_binary(binary_addr + 1))

def branch_operand(mnemonic, binary_addr, target):
    """The output for the relative branch at binary_addr to the (wrapped)
    target: the target's label, or, for a branch that wraps round the top
    or bottom of memory, the assembler's way of writing that (see
    Assembler.wrapped_branch_operand())."""
    label = disassembly.get_label(target, binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
    unwrapped = branch_target(binary_addr)
    if not 0 <= unwrapped < 0x10000:
        label = config.get_assembler().wrapped_branch_operand(label, unwrapped - movemanager.b2r(binary_addr))
    return output.Instruction(mnemonic, label)

class Cpu6502(cpu.Cpu):
    """Class representing a 6502 CPU (see the module's description).

    'opcodes' maps each documented opcode to an instance of one of the
    Opcode classes below. EMPTY_STATE is a CpuState with nothing known, used
    by the analysis where nothing is known (e.g. before code that follows
    data). The Cpu6510 and Cpu65C02
    classes add to the opcode table, and can add their own opcode classes.

    parse_instruction() and parse_instruction_template() are called on the
    class, without an instance (they have no 'self')."""

    # Addressing modes (an opcode's 'addr_mode'; also used by
    # jsonoutput.py): e.g. mode_offset is a branch's, mode_indexed_indirect
    # is (zp,X), mode_indirect_indexed is (zp),Y, mode_indirect_zp is the
    # 65C02's (zp), and mode_indirect_addr is JMP (addr)
    mode_implied           = 0
    mode_immediate         = 1
    mode_accumulator       = 2
    mode_offset            = 3
    mode_indexed_indirect  = 4
    mode_indirect_indexed  = 5
    mode_abs_indexed_x     = 6
    mode_zp_indexed_x      = 7
    mode_abs_indexed_y     = 8
    mode_zp_indexed_y      = 9
    mode_indirect_zp       = 10
    mode_indirect_addr     = 11
    mode_addr              = 12
    mode_zp                = 13
    mode_indexed_abs       = 14     # for the 65C02: JMP (addr,X)

    # Regex patterns that help identify the addressing modes (see
    # parse_instruction(), which tries them in this order). The mnemonic
    # must be three letters. Where zero page and absolute addressing are
    # written the same way (e.g. 'lda foo,x'), one pattern matches both.
    implied_pattern             = re.compile(r"([A-Z][A-Z][A-Z])$", re.IGNORECASE)
    immediate_pattern           = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+#(.+)$", re.IGNORECASE)
    accumulator_pattern         = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+A$", re.IGNORECASE)
    offset_pattern              = re.compile(r"(BPL|BMI|BVC|BVS|BCC|BCS|BNE|BEQ|BRA)[ \t]+(.+)$", re.IGNORECASE)
    indexed_indirect_pattern    = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+\((.*),X\)$", re.IGNORECASE)
    indirect_indexed_pattern    = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+\((.*)\),Y$", re.IGNORECASE)
    abs_or_zp_indexed_x_pattern = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+(.+),X$", re.IGNORECASE)
    abs_or_zp_indexed_y_pattern = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+(.+),Y$", re.IGNORECASE)
    indirect_pattern            = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+\((.*)\)$", re.IGNORECASE)
    zp_or_addr_pattern          = re.compile(r"([A-Z][A-Z][A-Z])[ \t]+(.+)$", re.IGNORECASE)

    # How instructions set the Z flag (see z_source()): the mnemonics that
    # don't change it, and those whose result (in the given registers) sets
    # it. (They include the 65C02's and the 6510's undocumented opcodes, and
    # some of other 65C02s, e.g. BBR0 and WAI, which py8dis doesn't trace.)
    Z_UNCHANGED = "unchanged"
    _Z_UNCHANGED_MNEMONICS = set("""
        sta stx sty stz sax sha shx shy tas jmp jsr bcc bcs beq bne bmi bpl bvc bvs bra
        nop pha php phx phy txs clc sec cli sei clv cld sed wai stp""".split()) | {
        "%s%d" % (op, bit) for op in ("bbr", "bbs", "rmb", "smb") for bit in range(8)}
    _Z_RESULT_REGISTERS = {
        "lda": ("a",), "pla": ("a",), "txa": ("a",), "tya": ("a",), "and": ("a",), "ora": ("a",),
        "eor": ("a",), "adc": ("a",), "sbc": ("a",), "anc": ("a",), "alr": ("a",), "arr": ("a",), "ane": ("a",),
        "ldx": ("x",), "tax": ("x",), "tsx": ("x",), "inx": ("x",), "dex": ("x",), "plx": ("x",), "sbx": ("x",),
        "ldy": ("y",), "tay": ("y",), "iny": ("y",), "dey": ("y",), "ply": ("y",),
        "slo": ("a",), "rla": ("a",), "sre": ("a",), "rra": ("a",), "isc": ("a",),
        "lax": ("a", "x"), "lxa": ("a", "x"), "las": ("a", "x"),
    }
    _Z_ACCUMULATOR_MNEMONICS = {"asl", "lsr", "rol", "ror", "inc", "dec"}
    _Z_COMPARE_REGISTERS = {"cmp": "a", "cpx": "x", "cpy": "y"}

    @staticmethod
    def z_source(opcode, binary_addr):
        """What the Z flag says about the registers after the instruction
        (see CpuStateDisposition.z_from): Z_UNCHANGED if it doesn't change Z,
        (registers, 0, binary_addr) if Z is set by its result in those
        registers (e.g. DEY, LDA, AND), ((register,), n, binary_addr) for a
        compare with an immediate n, otherwise None."""
        mnemonic = opcode.mnemonic.lower()
        if mnemonic in Cpu6502._Z_UNCHANGED_MNEMONICS:
            return Cpu6502.Z_UNCHANGED
        binary_addr = BinaryAddr(binary_addr)
        if mnemonic in Cpu6502._Z_RESULT_REGISTERS:
            return (Cpu6502._Z_RESULT_REGISTERS[mnemonic], 0, binary_addr)
        if mnemonic in Cpu6502._Z_ACCUMULATOR_MNEMONICS and opcode.addr_mode == Cpu6502.mode_accumulator:
            return (("a",), 0, binary_addr)
        if mnemonic in Cpu6502._Z_COMPARE_REGISTERS and opcode.addr_mode == Cpu6502.mode_immediate:
            return ((Cpu6502._Z_COMPARE_REGISTERS[mnemonic],), session.current().memory.binary[binary_addr + 1], binary_addr)
        return None

    class CpuState:
        """What's known about the CPU after an instruction (see
        Cpu.cpu_states), in two versions (CpuStateDispositions):

        - 'pessimistic' is what's known for certain. It's forgotten at each
          label, since code can come there from elsewhere. It's used for
          what py8dis says as fact, e.g. 'Y=1' comments, 'ALWAYS branch'
          and config.set_show_cpu_state(True);
        - 'optimistic' takes the code to have run straight through from the
          instruction before, even past a label. It's used to find where
          registers were set up, e.g. for a call (subroutine()) or a
          constant (substitute_constants()).

        Both are forgotten after a jump, call or return (the subroutine
        could change anything), and after a branch that's always taken.

        'always_branch' is True after a conditional branch that's always
        taken (its flag is known to make it branch). 'next_instruction' and
        'next_use' are set for a subroutine's hook (see
        find_subroutine_calls())."""

        def __init__(self):
            """Nothing is known to start with."""
            self.optimistic  = CpuStateDisposition()
            self.pessimistic = CpuStateDisposition()
            self.always_branch = False
            self.next_instruction = None

        def copy(self):
            """A fast copy (much faster than copy.deepcopy()). Any attribute
            with a copy() method (e.g. the dispositions, or a dict) is copied
            with it, others are immutable values."""
            result = type(self).__new__(type(self))
            result.__dict__ = {key: (value.copy() if hasattr(value, "copy") else value) for key, value in self.__dict__.items()}
            return result

        def clear(self, *, pessimistic_only):
            """Forget what's known: the pessimistic version only (e.g. at a
            label), or both."""
            self.pessimistic.clear()
            self.always_branch = False
            self.next_instruction = None
            if not pessimistic_only:
                self.optimistic.clear()

        def show(self):
            """The CPU state, for config.set_show_cpu_state(True): what's
            known for certain (i.e. pessimistically)."""
            return self.pessimistic.show()

    def memory_regions(self):
        """The 6502's zero page, stack and vectors."""
        # (The NMI, reset and IRQ/BRK vectors are at $fffa-$ffff.)
        return [(0x0000, 0x0100, "Zero page"),
                (0x0100, 0x0200, "Stack"),
                (0xfffa, 0x10000, "6502 vectors")]

    def __init__(self):
        """Make the opcode table, and add the code analysis functions."""
        super().__init__()

        self.EMPTY_STATE = self.CpuState()

        # The effect patterns' matches (see find_entry_points_from_effects()):
        # the latest for each snippet (by index), and the keys of those whose
        # pre-trace function has been called
        self.effect_matches = {}
        self.effect_matches_seen = set()

        self.code_analysis_fns.append(self.subroutine_argument_finder)  # For trace.subroutine_argument_finder_hooks (see subroutine_argument_finder())
        self.code_analysis_fns.append(self.substitute_constants)        # For the substitute_constants() command
        self.code_analysis_fns.append(self.find_subroutine_calls)       # For the subroutine() command
        self.code_analysis_fns.append(self.show_register_knowledge)     # Show places where we use an inferred value of a register.
        self.code_analysis_fns.append(self.find_redundant_instructions) # Comment instructions whose results are never used.

        # For labelling rts instructions numerically (see label_maker()): the
        # last number used, and the number of each RTS, by binary address
        self.return_index = 0
        self.return_array = {}

        # indent_level_dict has binary addresses as the keys, and indent values as the values.
        self.indent_level_dict = collections.defaultdict(int)

        # The opcode table. Each opcode object is made from: the instruction
        # template (the operand is 'zp' for a zero page address, 'addr' for
        # an absolute one, 'imm' for an immediate value and 'offset' for a
        # branch's); how it affects A, X and Y (see below); its cycle count
        # (a letter at the end says how it can vary: see
        # Opcode.cycles_description()); whether there's also an absolute
        # version of a zero page instruction, or a zero page version of an
        # absolute one; and the function that updates the CPU state for its
        # effect on the flags and the registers' values (see
        # Opcode.update_cpu_state()). Jumps, calls and returns have none,
        # since nothing is known after them.
        #
        # Each opcode is categorised by how it affects A:
        #
        # (-) Does not touch A                   (e.g. CLC, PHP, LDX)
        # (U) Uses A, but doesn't change it      (e.g. CMP, STA, PHA)
        # (A) Adjusts A, via arithmetic/bitwise  (e.g. ASL, ADC, AND)
        # (O) Overwrites A completely.           (e.g. LDA, PLA)
        # (T) Overwrites A with another register (e.g. TXA, TYA)
        #
        # ...and similarly for the X and Y registers.
        self.opcodes = {
            0x00: self.OpcodeReturn(            "BRK",        "---", cycles="7"),
            0x01: self.OpcodeZp(                "ORA (zp,X)", "AU-", cycles="6", has_abs_version=False, update=self.update_clear_nza),
            0x05: self.OpcodeZp(                "ORA zp",     "A--", cycles="3", update=self.update_clear_nza),
            0x06: self.OpcodeZp(                "ASL zp",     "---", cycles="5", update=self.update_clear_nzc),
            0x08: self.OpcodeImplied(           "PHP",        "---", cycles="3", update=self.neutral),
            0x09: self.OpcodeImmediate(         "ORA #imm",   "A--", cycles="2", update=self.update_ORA_immediate),
            0x0a: self.OpcodeImplied(           "ASL A",      "A--", cycles="2", update=self.update_clear_nzca),
            0x0d: self.OpcodeDataAbs(           "ORA addr",   "A--", cycles="4", update=self.update_clear_nza),
            0x0e: self.OpcodeDataAbs(           "ASL addr",   "---", cycles="6", update=self.update_clear_nzc),
            0x10: self.OpcodeConditionalBranch( "BPL offset", "---", cycles="2a", update=self.make_branch('n', True)),
            0x11: self.OpcodeZp(                "ORA (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_clear_nza),
            0x15: self.OpcodeZp(                "ORA zp,X",   "AU-", cycles="4",  update=self.update_clear_nza),
            0x16: self.OpcodeZp(                "ASL zp,X",   "-U-", cycles="6",  update=self.update_clear_nzc),
            0x18: self.OpcodeImplied(           "CLC",        "---", cycles="2",  update=self.make_update_flag('c', False)),
            0x19: self.OpcodeDataAbs(           "ORA addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_clear_nza),
            0x1d: self.OpcodeDataAbs(           "ORA addr,X", "AU-", cycles="4f", update=self.update_clear_nza),
            0x1e: self.OpcodeDataAbs(           "ASL addr,X", "-U-", cycles="7",  update=self.update_clear_nzc),
            0x20: self.OpcodeJsr(               "JSR addr",   "---", cycles="6"),
            0x21: self.OpcodeZp(                "AND (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_clear_nza),
            0x24: self.OpcodeZp(                "BIT zp",     "U--", cycles="3",  update=self.update_bit),
            0x25: self.OpcodeZp(                "AND zp",     "A--", cycles="3",  update=self.update_clear_nza),
            0x26: self.OpcodeZp(                "ROL zp",     "---", cycles="5",  update=self.update_clear_nzc),
            0x28: self.OpcodeImplied(           "PLP",        "---", cycles="4",  update=self.update_all_flags),
            0x29: self.OpcodeImmediate(         "AND #imm",   "A--", cycles="2",  update=self.update_AND_immediate),
            0x2a: self.OpcodeImplied(           "ROL A",      "A--", cycles="2",  update=self.update_clear_nzca),
            0x2c: self.OpcodeDataAbs(           "BIT addr",   "U--", cycles="4",  update=self.update_bit),
            0x2d: self.OpcodeDataAbs(           "AND addr",   "A--", cycles="4",  update=self.update_clear_nza),
            0x2e: self.OpcodeDataAbs(           "ROL addr",   "---", cycles="6",  update=self.update_clear_nzc),
            0x30: self.OpcodeConditionalBranch( "BMI offset", "---", cycles="2a", update=self.make_branch('n', False)),
            0x31: self.OpcodeZp(                "AND (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_clear_nza),
            0x35: self.OpcodeZp(                "AND zp,X",   "AU-", cycles="4",  update=self.update_clear_nza),
            0x36: self.OpcodeZp(                "ROL zp,X",   "-U-", cycles="6",  update=self.update_clear_nzc),
            0x38: self.OpcodeImplied(           "SEC",        "---", cycles="2",  update=self.make_update_flag('c', True)),
            0x39: self.OpcodeDataAbs(           "AND addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_clear_nza),
            0x3d: self.OpcodeDataAbs(           "AND addr,X", "AU-", cycles="4f", update=self.update_clear_nza),
            0x3e: self.OpcodeDataAbs(           "ROL addr,X", "-U-", cycles="7",  update=self.update_clear_nzc),
            0x40: self.OpcodeReturn(            "RTI",        "---", cycles="6"),
            0x41: self.OpcodeZp(                "EOR (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_clear_nza),
            0x45: self.OpcodeZp(                "EOR zp",     "A--", cycles="3",  update=self.update_clear_nza),
            0x46: self.OpcodeZp(                "LSR zp",     "---", cycles="5",  update=self.update_clear_nzc),
            0x48: self.OpcodeImplied(           "PHA",        "U--", cycles="3",  update=self.neutral),
            0x49: self.OpcodeImmediate(         "EOR #imm",   "A--", cycles="2",  update=self.update_clear_nza),
            0x4a: self.OpcodeImplied(           "LSR A",      "A--", cycles="2",  update=self.update_clear_nzca),
            0x4c: self.OpcodeJmpAbs(            "JMP addr",   "---", cycles="3"),
            0x4d: self.OpcodeDataAbs(           "EOR addr",   "A--", cycles="4",  update=self.update_clear_nza),
            0x4e: self.OpcodeDataAbs(           "LSR addr",   "---", cycles="6",  update=self.update_clear_nzc),
            0x50: self.OpcodeConditionalBranch( "BVC offset", "---", cycles="2a", update=self.make_branch('v', True)),
            0x51: self.OpcodeZp(                "EOR (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_clear_nza),
            0x55: self.OpcodeZp(                "EOR zp,X",   "AU-", cycles="4",  update=self.update_clear_nza),
            0x56: self.OpcodeZp(                "LSR zp,X",   "-U-", cycles="6",  update=self.update_clear_nzc),
            0x58: self.OpcodeImplied(           "CLI",        "---", cycles="2",  update=self.make_update_flag('i', False)),
            0x59: self.OpcodeDataAbs(           "EOR addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_clear_nza),
            0x5d: self.OpcodeDataAbs(           "EOR addr,X", "AU-", cycles="4f", update=self.update_clear_nza),
            0x5e: self.OpcodeDataAbs(           "LSR addr,X", "-U-", cycles="7",  update=self.update_clear_nzc),
            0x60: self.OpcodeReturn(            "RTS",        "---", cycles="6"),
            0x61: self.OpcodeZp(                "ADC (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_adc_sbc),
            0x65: self.OpcodeZp(                "ADC zp",     "A--", cycles="3",  update=self.update_adc_sbc),
            0x66: self.OpcodeZp(                "ROR zp",     "---", cycles="5",  update=self.update_clear_nzc),
            0x68: self.OpcodeImplied(           "PLA",        "O--", cycles="4",  update=self.update_clear_nz),
            0x69: self.OpcodeImmediate(         "ADC #imm",   "A--", cycles="2",  update=self.update_adc_sbc),
            0x6a: self.OpcodeImplied(           "ROR A",      "A--", cycles="2",  update=self.update_rora),
            0x6c: self.OpcodeJmpInd(            "JMP (addr)", "---", cycles="5"),
            0x6d: self.OpcodeDataAbs(           "ADC addr",   "A--", cycles="4",  update=self.update_adc_sbc),
            0x6e: self.OpcodeDataAbs(           "ROR addr",   "---", cycles="6",  update=self.update_clear_nzc),
            0x70: self.OpcodeConditionalBranch( "BVS offset", "---", cycles="2a", update=self.make_branch('v', False)),
            0x71: self.OpcodeZp(                "ADC (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_adc_sbc),
            0x75: self.OpcodeZp(                "ADC zp,X",   "AU-", cycles="4",  update=self.update_adc_sbc),
            0x76: self.OpcodeZp(                "ROR zp,X",   "-U-", cycles="6",  update=self.update_clear_nzc),
            0x78: self.OpcodeImplied(           "SEI",        "---", cycles="2",  update=self.make_update_flag('i', True)),
            0x79: self.OpcodeDataAbs(           "ADC addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_adc_sbc),
            0x7d: self.OpcodeDataAbs(           "ADC addr,X", "AU-", cycles="4f", update=self.update_adc_sbc),
            0x7e: self.OpcodeDataAbs(           "ROR addr,X", "-U-", cycles="7",  update=self.update_clear_nzc),
            0x81: self.OpcodeZp(                "STA (zp,X)", "UU-", cycles="6",  has_abs_version=False, update=self.neutral),
            0x84: self.OpcodeZp(                "STY zp",     "--U", cycles="3",  update=self.neutral),
            0x85: self.OpcodeZp(                "STA zp",     "U--", cycles="3",  update=self.neutral),
            0x86: self.OpcodeZp(                "STX zp",     "-U-", cycles="3",  update=self.neutral),
            0x88: self.OpcodeImplied(           "DEY",        "--A", cycles="2",  update=self.make_decrement('y')),
            0x8a: self.OpcodeImplied(           "TXA",        "TU-", cycles="2",  update=self.make_transfer('x', 'a')),
            0x8c: self.OpcodeDataAbs(           "STY addr",   "--U", cycles="4",  update=self.neutral),
            0x8d: self.OpcodeDataAbs(           "STA addr",   "U--", cycles="4",  update=self.neutral),
            0x8e: self.OpcodeDataAbs(           "STX addr",   "-U-", cycles="4",  update=self.neutral),
            0x90: self.OpcodeConditionalBranch( "BCC offset", "---", cycles="2a", update=self.make_branch('c', True)),
            0x91: self.OpcodeZp(                "STA (zp),Y", "U-U", cycles="6",  has_abs_version=False, update=self.neutral),
            0x94: self.OpcodeZp(                "STY zp,X",   "-UU", cycles="4",  update=self.neutral),
            0x95: self.OpcodeZp(                "STA zp,X",   "UU-", cycles="4",  update=self.neutral),
            0x96: self.OpcodeZp(                "STX zp,Y",   "-UU", cycles="4",  update=self.neutral),
            0x98: self.OpcodeImplied(           "TYA",        "T-U", cycles="2",  update=self.make_transfer('y', 'a')),
            0x99: self.OpcodeDataAbs(           "STA addr,Y", "U-U", cycles="5",  has_zp_version=False, update=self.neutral),
            0x9a: self.OpcodeImplied(           "TXS",        "-U-", cycles="2",  update=self.neutral), # we don't model S at all
            0x9d: self.OpcodeDataAbs(           "STA addr,X", "UU-", cycles="5",  update=self.neutral),
            0xa0: self.OpcodeImmediate(         "LDY #imm",   "--O", cycles="2",  update=self.make_load_immediate('y')),
            0xa1: self.OpcodeZp(                "LDA (zp,X)", "OU-", cycles="6",  has_abs_version=False, update=self.update_clear_nz),
            0xa2: self.OpcodeImmediate(         "LDX #imm",   "-O-", cycles="2",  update=self.make_load_immediate('x')),
            0xa4: self.OpcodeZp(                "LDY zp",     "--O", cycles="3",  update=self.update_clear_nz),
            0xa5: self.OpcodeZp(                "LDA zp",     "O--", cycles="3",  update=self.update_clear_nz),
            0xa6: self.OpcodeZp(                "LDX zp",     "-O-", cycles="3",  update=self.update_clear_nz),
            0xa8: self.OpcodeImplied(           "TAY",        "U-T", cycles="2",  update=self.make_transfer('a', 'y')),
            0xa9: self.OpcodeImmediate(         "LDA #imm",   "O--", cycles="2",  update=self.make_load_immediate('a')),
            0xaa: self.OpcodeImplied(           "TAX",        "UT-", cycles="2",  update=self.make_transfer('a', 'x')),
            0xac: self.OpcodeDataAbs(           "LDY addr",   "--O", cycles="4",  update=self.update_clear_nz),
            0xad: self.OpcodeDataAbs(           "LDA addr",   "O--", cycles="4",  update=self.update_clear_nz),
            0xae: self.OpcodeDataAbs(           "LDX addr",   "-O-", cycles="4",  update=self.update_clear_nz),
            0xb0: self.OpcodeConditionalBranch( "BCS offset", "---", cycles="2a", update=self.make_branch('c', False)),
            0xb1: self.OpcodeZp(                "LDA (zp),Y", "O-U", cycles="5b", has_abs_version=False, update=self.update_clear_nz),
            0xb4: self.OpcodeZp(                "LDY zp,X",   "-UO", cycles="4",  update=self.update_clear_nz),
            0xb5: self.OpcodeZp(                "LDA zp,X",   "OU-", cycles="4",  update=self.update_clear_nz),
            0xb6: self.OpcodeZp(                "LDX zp,Y",   "-OU", cycles="4",  update=self.update_clear_nz),
            0xb8: self.OpcodeImplied(           "CLV",        "---", cycles="2",  update=self.make_update_flag('v', False)),
            0xb9: self.OpcodeDataAbs(           "LDA addr,Y", "O-U", cycles="4f", has_zp_version=False, update=self.update_clear_nz),
            0xba: self.OpcodeImplied(           "TSX",        "-O-", cycles="2",  update=self.update_clear_nz),
            0xbc: self.OpcodeDataAbs(           "LDY addr,X", "-UO", cycles="4f", update=self.update_clear_nz),
            0xbd: self.OpcodeDataAbs(           "LDA addr,X", "OU-", cycles="4f", update=self.update_clear_nz),
            0xbe: self.OpcodeDataAbs(           "LDX addr,Y", "-OU", cycles="4f", update=self.update_clear_nz),
            0xc0: self.OpcodeImmediate(         "CPY #imm",   "--U", cycles="2",  update=self.update_compare),
            0xc1: self.OpcodeZp(                "CMP (zp,X)", "UU-", cycles="6",  has_abs_version=False, update=self.update_compare),
            0xc4: self.OpcodeZp(                "CPY zp",     "--U", cycles="3",  update=self.update_compare),
            0xc5: self.OpcodeZp(                "CMP zp",     "U--", cycles="3",  update=self.update_compare),
            0xc6: self.OpcodeZp(                "DEC zp",     "---", cycles="5",  update=self.update_clear_nz),
            0xc8: self.OpcodeImplied(           "INY",        "--A", cycles="2",  update=self.make_increment('y')),
            0xc9: self.OpcodeImmediate(         "CMP #imm",   "U--", cycles="2",  update=self.update_compare),
            0xca: self.OpcodeImplied(           "DEX",        "-A-", cycles="2",  update=self.make_decrement('x')),
            0xcc: self.OpcodeDataAbs(           "CPY addr",   "--U", cycles="4",  update=self.update_compare),
            0xcd: self.OpcodeDataAbs(           "CMP addr",   "U--", cycles="4",  update=self.update_compare),
            0xce: self.OpcodeDataAbs(           "DEC addr",   "---", cycles="6",  update=self.update_clear_nz),
            0xd0: self.OpcodeConditionalBranch( "BNE offset", "---", cycles="2a", update=self.make_branch('z', True)),
            0xd1: self.OpcodeZp(                "CMP (zp),Y", "U-U", cycles="5b", has_abs_version=False, update=self.update_compare),
            0xd5: self.OpcodeZp(                "CMP zp,X",   "UU-", cycles="4",  update=self.update_compare),
            0xd6: self.OpcodeZp(                "DEC zp,X",   "-U-", cycles="6",  update=self.update_clear_nz),
            0xd8: self.OpcodeImplied(           "CLD",        "---", cycles="2",  update=self.make_update_flag('d', False)),
            0xd9: self.OpcodeDataAbs(           "CMP addr,Y", "U-U", cycles="4f", has_zp_version=False, update=self.update_compare),
            0xdd: self.OpcodeDataAbs(           "CMP addr,X", "UU-", cycles="4f", update=self.update_compare),
            0xde: self.OpcodeDataAbs(           "DEC addr,X", "-U-", cycles="7",  update=self.update_clear_nz),
            0xe0: self.OpcodeImmediate(         "CPX #imm",   "-U-", cycles="2",  update=self.update_compare),
            0xe1: self.OpcodeZp(                "SBC (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_adc_sbc),
            0xe4: self.OpcodeZp(                "CPX zp",     "-U-", cycles="3",  update=self.update_compare),
            0xe5: self.OpcodeZp(                "SBC zp",     "A--", cycles="3",  update=self.update_adc_sbc),
            0xe6: self.OpcodeZp(                "INC zp",     "---", cycles="5",  update=self.update_clear_nz),
            0xe8: self.OpcodeImplied(           "INX",        "-A-", cycles="2",  update=self.make_increment('x')),
            0xe9: self.OpcodeImmediate(         "SBC #imm",   "A--", cycles="2",  update=self.update_adc_sbc),
            0xea: self.OpcodeImplied(           "NOP",        "---", cycles="2",  update=self.neutral),
            0xec: self.OpcodeDataAbs(           "CPX addr",   "-U-", cycles="4",  update=self.update_compare),
            0xed: self.OpcodeDataAbs(           "SBC addr",   "A--", cycles="4",  update=self.update_adc_sbc),
            0xee: self.OpcodeDataAbs(           "INC addr",   "---", cycles="6",  update=self.update_clear_nz),
            0xf0: self.OpcodeConditionalBranch( "BEQ offset", "---", cycles="2a", update=self.make_branch('z', False)),
            0xf1: self.OpcodeZp(                "SBC (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_adc_sbc),
            0xf5: self.OpcodeZp(                "SBC zp,X",   "AU-", cycles="4",  update=self.update_adc_sbc),
            0xf6: self.OpcodeZp(                "INC zp,X",   "-U-", cycles="6",  update=self.update_clear_nz),
            0xf8: self.OpcodeImplied(           "SED",        "---", cycles="2",  update=self.make_update_flag('d', True)),
            0xf9: self.OpcodeDataAbs(           "SBC addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_adc_sbc),
            0xfd: self.OpcodeDataAbs(           "SBC addr,X", "AU-", cycles="4f", update=self.update_adc_sbc),
            0xfe: self.OpcodeDataAbs(           "INC addr,X", "-U-", cycles="7",  update=self.update_clear_nz),
        }

    def get_target_binary_addr_preferring_given_move_id(self, runtime_addr, specific_move_id):
        """The binary address for the runtime address, in the given move if
        that has the address, else in the one move that has it (or the
        active one, if more than one has it: see movemanager.r2b()), as a
        list (empty if neither is found). For where a JSR returns to."""
        binary_addr, _ = movemanager.r2b(runtime_addr, specific_move_id)
        if binary_addr is None:
            binary_addr, _ = movemanager.r2b(runtime_addr)
            if binary_addr is None:
                return []
        return [binary_addr]

    def parse_instruction(instruction):
        """Parse an instruction written in assembly language, e.g. 'sta
        $d020', 'jsr sprite_plot' (for SubConst) or 'LDA (zp),Y' (an opcode
        template), as (mnemonic, operand, operand length, prefix, suffix,
        addressing modes). The prefix and suffix are what's written around
        the operand (e.g. '(' and '),Y'). The addressing modes are a list of
        one, or of two where the operand could be zero page or absolute (the
        zero page one first): the operand length is then 1, to be decided
        later (except for 'operand,X', where it's [1, 2]).

        Stops with utils.die() if it can't parse it. (Called on the class,
        as Cpu6502.parse_instruction().)"""
        instruction = instruction.strip()
        r = re.match(Cpu6502.implied_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = ""
            operand_length  = 0
            prefix          = ""
            suffix          = ""
            addr_mode       = [Cpu6502.mode_implied]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.immediate_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1
            prefix          = "#"
            suffix          = ""
            addr_mode       = [Cpu6502.mode_immediate]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.accumulator_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = ""
            operand_length  = 0
            # (Some assemblers want 'asl a', others just 'asl': see
            # Assembler.explicit_a)
            if config.get_assembler().explicit_a:
                prefix = "A"
            else:
                prefix = ""
            suffix          = ""
            addr_mode       = [Cpu6502.mode_accumulator]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.offset_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1
            prefix          = ""
            suffix          = ""
            addr_mode       = [Cpu6502.mode_offset]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.indexed_indirect_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            prefix          = "("
            suffix          = ",X)"

            # (The 65C02's JMP (addr,X) has a two byte address, unlike (zp,X))
            if mnemonic == "JMP":
                operand_length = 2
                addr_mode      = [Cpu6502.mode_indexed_abs]
            else:
                operand_length  = 1
                addr_mode       = [Cpu6502.mode_indexed_indirect]

            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.indirect_indexed_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1
            prefix          = "("
            suffix          = "),Y"
            addr_mode       = [Cpu6502.mode_indirect_indexed]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.abs_or_zp_indexed_x_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = [1, 2]
            prefix          = ""
            suffix          = ",X"
            addr_mode       = [Cpu6502.mode_zp_indexed_x, Cpu6502.mode_abs_indexed_x]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.abs_or_zp_indexed_y_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1 # Could be two, updated later
            prefix          = ""
            suffix          = ",Y"
            addr_mode       = [Cpu6502.mode_zp_indexed_y, Cpu6502.mode_abs_indexed_y]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.indirect_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1 # Could be two, updated later
            prefix          = "("
            suffix          = ")"
            addr_mode       = [Cpu6502.mode_indirect_zp, Cpu6502.mode_indirect_addr]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        r = re.match(Cpu6502.zp_or_addr_pattern, instruction)
        if r:
            mnemonic        = r.groups(1)[0]
            operand         = r.groups(1)[1]
            operand_length  = 1 # Could be two, updated later
            prefix          = ""
            suffix          = ""
            addr_mode       = [Cpu6502.mode_zp, Cpu6502.mode_addr]
            return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

        utils.die("Could not understand instruction: %s" % (instruction))
        return None

    def parse_instruction_template(instruction):
        """Parse an opcode template from the opcode table (e.g. 'LDA zp,X'
        or 'JMP (addr)') as parse_instruction() does, but with one
        addressing mode and operand length: where it could be zero page or
        absolute, the operand's name says which ('zp', one byte, or 'addr',
        two). Stops with utils.die() if it's neither. (Called on the class,
        as Cpu6502.parse_instruction_template().)"""
        mnemonic, operand, operand_length, prefix, suffix, addr_mode = Cpu6502.parse_instruction(instruction)

        if len(addr_mode) == 1:
            addr_mode = addr_mode[0]
        elif len(addr_mode) > 1:
            # Resolve zp vs addr addressing modes
            if operand == "zp":
                operand_length = 1
                addr_mode = addr_mode[0]
            elif operand == "addr":
                operand_length = 2
                addr_mode = addr_mode[1]
            else:
                utils.warn("%s, %s, %s, %s, %s, %s" % (mnemonic, operand, operand_length, prefix, suffix, addr_mode))
                utils.die("Could not understand instruction template %s" % (instruction))

        return (mnemonic, operand, operand_length, prefix, suffix, addr_mode)

    def hook_subroutine(self, runtime_addr, name, hook):
        """Make runtime_addr an entry point, named 'name', and give it a
        subroutine hook (see commands.hook_subroutine()). When a JSR to it is
        traced, hook(target runtime address, JSR's runtime address) is
        called to say where the code goes on after the call: it returns a
        runtime address, or None if the subroutine doesn't return there
        (see OpcodeJsr.disassemble())."""
        runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        self.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, name, explicit=True)
        self.subroutine_hooks[runtime_addr] = hook

    @staticmethod
    def is_private_register_description(description):
        """A register description in brackets, e.g. '(preserved)', is shown in
        the subroutine header but is not used to decorate calling code."""
        return description.startswith("(") and description.endswith(")")

    def default_subroutine_hook(self, runtime_addr, state, subroutine):
        """The hook used for a subroutine() that isn't given one, called by
        find_subroutine_calls() with the runtime address of a call to the
        subroutine (or of the subroutine itself, where code runs on into
        it), the CPU state before it, and the Subroutine.

        It comments the instruction that last set each register the
        subroutine takes (e.g. 'X=channel', from its on_entry), the call
        with the subroutine's title, and the next use after the call of each
        register it returns (from its on_exit). Descriptions in brackets
        aren't used (see is_private_register_description())."""
        # Look for where we set up registers before the subroutine call
        for reg in ('a', 'x', 'y'):
            reg_addr = state.optimistic[reg].previous_adjust
            if reg_addr is not None:
                com = subroutine.on_entry.get(reg)
                if com and not self.is_private_register_description(com):
                    disassembly.comment_binary(reg_addr, reg.upper() + "=" + com, align=Align.INLINE, word_wrap=False, auto_generated=True)

        # Add subroutine title comment
        if subroutine.title and subroutine.runtime_addr != runtime_addr:
            disassembly.comment(runtime_addr, subroutine.title, align=Align.INLINE, word_wrap=False, auto_generated=True)

        # After the subroutine, check for results in registers being used
        if subroutine.on_exit:
            if subroutine.runtime_addr != runtime_addr:
                for reg in ('a', 'x', 'y'):
                    # The register may be used after the call without the
                    # subroutine saying anything about it on exit.
                    com = subroutine.on_exit.get(reg)
                    if not com or self.is_private_register_description(com):
                        continue
                    next_use = state.next_use[reg]
                    if next_use is not None:
                        reg_runtime_addr = movemanager.b2r(next_use)
                        disassembly.comment(reg_runtime_addr, reg.upper() + "=" + com, align=Align.INLINE, auto_generated=True)



    class Opcode:
        """An opcode: the base class of the opcode classes. One object is
        made for each opcode in the table, and it's also the classification
        of every instruction with that opcode (see classification.py), so
        its methods take the instruction's binary address.

        The derived classes provide disassemble() (where the code goes after
        the instruction, for tracing: see Cpu.disassemble_instruction()),
        update_references() (the label it refers to, if any) and
        instruction() (how it's written, as an output.Instruction).

        'reg_changes' is {'a', 'x', 'y': how the instruction affects the
        register (see regular_update())}. 'update' is the function that
        updates the CPU state for its effect on the flags and the registers'
        values (or None if nothing is known after it). 'cycles' is its cycle
        count (see cycles_description()). 'operand' is the operand's name in
        the template (e.g. 'zp'), and 'prefix' and 'suffix' what's written
        around the operand. (indent_level isn't used: the indents are in the
        CPU's indent_level_dict.)"""

        def __init__(self, instruction_template, reg_change, update=None, cycles="???"):
            """'reg_change' is how the instruction affects A, X and Y, as three
            letters (e.g. 'AU-': see regular_update())."""

            self.instruction_template = instruction_template

            mnemonic, operand, operand_length, prefix, suffix, addr_mode = Cpu6502.parse_instruction_template(instruction_template)

            self.mnemonic       = mnemonic
            self.operand        = operand
            self.operand_length = operand_length
            self.addr_mode      = addr_mode
            self.prefix         = prefix
            self.suffix         = suffix

            self.reg_changes    = {
                'a': reg_change[0],
                'x': reg_change[1],
                'y': reg_change[2]
            }

            self.update         = update
            self.indent_level   = 0
            self.cycles         = cycles


        def length(self):
            """The instruction's length in bytes."""
            return 1 + self.operand_length

        def is_code(self, binary_addr):
            """True: an instruction is code."""
            return True

        def indent(self, binary_addr):
            """Indent the instruction at binary_addr one more level in the
            output (it's in a loop: see disassembly.suggest_label_name())."""
            session.current().cpu.indent_level_dict[binary_addr] += 1

        def regular_update(self, binary_addr, state):
            """
            Update state based on reg_changes: which instruction last loaded,
            changed and used each register (the RegState's previous_*), in
            both versions of the state. (The update function deals with the
            values and flags, after this.) Also clears state.always_branch.

            Each opcode is categorised in reg_changes['a'] by how it affects A:

            (-) Does not touch A                   (e.g. CLC, PHP, LDX)
            (U) Uses A, but doesn't change it      (e.g. CMP, STA, PHA)
            (A) Adjusts A, via arithmetic/bitwise  (e.g. ASL, ADC, AND)
            (O) Overwrites A completely.           (e.g. LDA, PLA)
            (T) Overwrites A with another register (e.g. TXA, TYA)

            ...and similarly for the X and Y registers.

            'O' and 'T' make the register's value unknown and this
            instruction the one that loaded it, 'A' makes this the one that
            last changed it (forgetting where it was loaded), and 'U' makes
            this its last use.
            """
            binary_addr = BinaryAddr(binary_addr)
            state.always_branch = False
            for reg in ('a','x','y'):
                c = self.reg_changes[reg]
                if c == 'O' or c == 'T':
                    state.optimistic[reg].value               = None        # Current value, if known
                    state.optimistic[reg].previous_load_imm   = None        # The address of the previous load immediate instruction if no adjustments made since
                    state.optimistic[reg].previous_load       = binary_addr # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
                    state.optimistic[reg].previous_adjust     = binary_addr # The address of the previous load or adjust instruction if present

                    state.pessimistic[reg].value              = None        # Current value, if known
                    state.pessimistic[reg].previous_load_imm  = None        # The address of the previous load immediate instruction if no adjustments made since
                    state.pessimistic[reg].previous_load      = binary_addr # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
                    state.pessimistic[reg].previous_adjust    = binary_addr # The address of the previous load or adjust instruction if present
                if c == 'A':
                    state.optimistic[reg].previous_load_imm   = None        # The address of the previous load immediate instruction if no adjustments made since
                    state.optimistic[reg].previous_load       = None        # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
                    state.optimistic[reg].previous_adjust     = binary_addr # The address of the previous load or adjust instruction if present

                    state.pessimistic[reg].previous_load_imm  = None        # The address of the previous load immediate instruction if no adjustments made since
                    state.pessimistic[reg].previous_load      = None        # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
                    state.pessimistic[reg].previous_adjust    = binary_addr # The address of the previous load or adjust instruction if present
                if c == 'U':
                    state.optimistic[reg].previous_use        = binary_addr # The address of the previous use of the register if present
                    state.pessimistic[reg].previous_use       = binary_addr # The address of the previous use of the register if present

        def clear_pessimistic_state_if_label_here(self, binary_addr, state):
            """Forget what's known for certain if the instruction has a label
            (whether or not anything refers to it)."""
            # if there's a label at this address, then we lose all known (pessimistic) state.
            # This is because somewhere will be jumping to the label with unknown state.
            runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
            if runtime_addr is not None:
                if runtime_addr in session.current().labels.labels:
                    state.clear(pessimistic_only=True)

        def update_cpu_state(self, binary_addr, state):
            """Change 'state' (a CpuState) from what's known before the
            instruction at binary_addr to what's known after it (see
            Cpu.calculate_cpu_states()).

            At a label, what's known for certain is forgotten first. Then
            regular_update() and the update function change the state, and
            'z_from' says what Z now says about the registers (see
            z_source()). If code can start in the middle of the instruction
            (see is_entered_inside()), nothing is known for certain after
            it. Without an update function (a jump, call or return), nothing
            is known after the instruction."""
            # if there's a label at this address, then we lose all known pessimistic state.
            # This is because somewhere will be jumping to the label with unknown state.
            self.clear_pessimistic_state_if_label_here(binary_addr, state)

            # otherwise we update state if there's an update function
            if self.update is not None:
                self.regular_update(binary_addr, state)
                self.update(binary_addr, state)
                z_from = Cpu6502.z_source(self, binary_addr)
                if z_from is not Cpu6502.Z_UNCHANGED:
                    state.optimistic.z_from = z_from
                    state.pessimistic.z_from = z_from
                # Code that jumps into the middle of this instruction (the
                # BIT trick, e.g. 'bit $02a9' skipping 'lda #2') runs another
                # instruction there, then continues after this one, so
                # nothing is known for certain after it
                if session.current().cpu.is_entered_inside(binary_addr, self.length()):
                    state.clear(pessimistic_only=True)
            else:
                state.clear(pessimistic_only=False)

        def is_block_end(self):
            """Whether the instruction ends a block of code, i.e. the code
            doesn't run on into the next instruction (e.g. a jump or
            return). A block end gets a blank line after it, and ends a
            straight run (see Cpu6502.straight_runs()). False here."""
            return False

        def target(self, binary_addr):
            """The runtime address the instruction at binary_addr refers to
            (its operand's address, or a branch's target), or None if it has
            none. None here."""
            return None

        def cycles_description(self, binary_addr):
            """The instruction's cycle count, as text for the output (see
            config.set_show_cycles()): e.g. '4', or '4/5' where it can take
            an extra cycle. 'cycles' ends with a letter that says how it can
            vary (see below), if it can."""
            # Letter suffix on self.cycles explains cycle adjustments:
            #
            # a: +1 if branch occurs to same page, +2 if branch occurs to different page
            # b: +1 if page boundary crossed (zero page, post indirect addressing)
            # f: +1 if page boundary crossed (absolute address)

            # These three are 65c02 only:
            # c: +1 cycle if in decimal mode, +1 more cycle if indexing across a page boundary
            # d: +1 if branch target is to a different page
            # e: +1 cycle if in decimal mode
            #
            # (Without a letter, e.g. '6', or the 6510's JAM's 'halts', the
            # count is shown as it is.)

            def branch_is_to_same_page():
                """Whether the branch's target is in the same page as the
                next instruction."""
                # A taken branch costs an extra cycle if the target is in a
                # different page to the *next* instruction (where the program
                # counter is when the branch is taken). Both are runtime
                # addresses, so this works for move()d code too.
                next_instruction_runtime_addr = movemanager.b2r(binary_addr) + 2
                return (self.target(binary_addr) // 256) == (next_instruction_runtime_addr // 256)

            letter = self.cycles[-1]
            if letter == "a":
                # A branch instruction
                result = int(self.cycles[:-1])

                # Check the target address to see if it is in the same page
                same_page = branch_is_to_same_page()

                if same_page:
                    return str(result) + "/" + str(result+1)
                return str(result) + "/" + str(result+2)

            if letter == "b":
                # zero page post indexed addressing
                result = int(self.cycles[:-1])
                return str(result) + "/" + str(result+1)

            if letter == "f":
                # absolute address indexed by X or Y
                # we only know the exact cycle count if it's on a page boundary
                # since then we know it can't cross a page boundary.
                result = int(self.cycles[:-1])

                # Check the target address to see if it is on a page boundary
                target = self.target(binary_addr)
                if (target & 255) == 0:
                    return str(result)
                return str(result) + "/" + str(result+1)

            if letter == "c":
                result = int(self.cycles[:-1])
                return str(result) + "/" + str(result+1) + "/" + str(result+2)

            if letter == "d":
                result = int(self.cycles[:-1])

                # Check the target address to see if it is in the same page
                same_page = branch_is_to_same_page()

                if same_page:
                    return str(result)
                return str(result+1)

            if letter == "e":
                result = int(self.cycles[:-1])
                return str(result) + "/" + str(result+1)

            result = self.cycles
            return result

        def could_be_call_to_subroutine(self):
            """Whether the instruction sends the code to its target (a JSR,
            JMP or branch), so that the target could be a subroutine it
            calls (see find_subroutine_calls()). Also used to tell a jump
            into the middle of an instruction (see is_entered_inside()) from
            a data reference. False here."""
            return False

        def is_unconditional_branch(self):
            """Whether the instruction always sends the code somewhere else
            first (JSR, JMP (addr) and the 65C02's BRA), which ends
            scan_ahead_for_post_exit_state()'s search. False here (and for
            JMP addr, which ends the search by ending a block)."""
            return False

        def as_lines(self, binary_loc, annotations):
            """The output for the instruction at binary_loc, as a list of
            line objects (see output.py): the instruction (with its extra
            indent, cycle count and annotations), and a blank line after the
            end of a block if config.get_blank_line_at_block_end()."""
            binary_addr = binary_loc.binary_addr
            result = [self.instruction(binary_addr).placed(binary_loc, self.length(), session.current().cpu.indent_level_dict.get(binary_addr, 0),
                                                           self.cycles_description(binary_addr), annotations)]
            if self.is_block_end() and config.get_blank_line_at_block_end():
                result.append(output.Blank())
            return result

        def __repr__(self):
            return "{0}{1} {2}ADDR{3}".format(utils.make_indent(1),
                utils.force_case(self.mnemonic),
                self.prefix,
                utils.force_case(self.suffix))

        def __str__(self):
            return self.__repr__()

    class OpcodeReturn(Opcode):
        """An instruction after which tracing stops, since where the code
        goes next isn't known from the instruction: RTS, RTI and BRK (and
        the 6510's JAM). It has no update function, so nothing is known
        after it."""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, cycles=cycles)

        def update_references(self, binary_loc):
            """Nothing: there's no operand."""
            pass

        def disassemble(self, binary_loc):
            """Nothing more to trace from here."""
            return [None]

        def is_block_end(self):
            """True: the code doesn't run on."""
            return True

        def instruction(self, binary_addr):
            """Just the mnemonic."""
            return output.Instruction(self.mnemonic)


    class OpcodeImplied(Opcode):
        """An instruction with no operand (e.g. INX, CLC, PHA), or one that
        works on A (e.g. ASL A)."""

        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            """Nothing: there's no operand."""
            pass

        def disassemble(self, binary_loc):
            """The next instruction, one byte on."""
            return [binary_loc.binary_addr + 1]

        def instruction(self, binary_addr):
            """The mnemonic, with ' A' after it for an instruction on A if
            the assembler wants that (Assembler.explicit_a)."""
            mnemonic = self.mnemonic
            if config.get_assembler().explicit_a and (self.addr_mode == Cpu6502.mode_accumulator):
                mnemonic += " A"
            return output.Instruction(mnemonic)


    class OpcodeImmediate(Opcode):
        """An instruction with an immediate operand (e.g. LDA #imm)."""

        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            """Nothing: the operand isn't an address."""
            pass

        def disassemble(self, binary_loc):
            """The next instruction, two bytes on."""
            return [binary_loc.binary_addr + 2]

        def instruction(self, binary_addr):
            """The instruction, with its operand as a number, constant or
            expression (see classification.get_constant8()). If the operand
            is a printable character (in the session's text encoding) and
            isn't given an expression or a format, the character is shown in
            a comment too (see config.set_show_char_literals()). So is one
            that char() asks for, if the assembler can't write it as a
            character."""
            memory_binary = session.current().memory.binary
            operand = classification.get_constant8(binary_addr + 1)
            char_literal = None
            format_hint = session.current().disassembly.format_hint.get(binary_addr + 1)
            if format_hint is mainformatter.char_formatter and config.get_assembler().encoded_char_literal(memory_binary[binary_addr + 1], textencoding.current()) is None:
                # (char() asks for a character, but the assembler can't
                # write it as one, so it's a number, with the comment)
                format_hint = None
            if (binary_addr + 1) not in session.current().classifications.expressions and format_hint is None:
                c = memory_binary[binary_addr + 1]
                # (In the session's text encoding, see config.set_text_encoding())
                char = textencoding.current().char(c)
                if config.get_show_char_literals() and char is not None:
                    char_literal = "'%s'" % char
            return output.Instruction(self.mnemonic, operand, prefix="#", char_literal=char_literal)


    class OpcodeZp(Opcode):
        """An instruction with a zero page address as its operand (one
        byte): zp, zp,X, zp,Y, (zp,X), (zp),Y and the 65C02's (zp).
        has_abs_version says whether there's an absolute version of the
        instruction too (it isn't used)."""

        def __init__(self, instruction_template, reg_change, has_abs_version=True, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, update=update, cycles=cycles)
            self._has_abs_version = has_abs_version

        def abs_operand(self, binary_addr):
            """The operand: a zero page address, as a runtime address."""
            memory_binary = session.current().memory.binary
            return memorymanager.RuntimeAddr(memory_binary[binary_addr + 1])

        def target(self, binary_addr):
            """The operand's address."""
            return memorymanager.RuntimeAddr(self.abs_operand(binary_addr))

        def update_references(self, binary_loc):
            """The operand's address gets a label (if it hasn't one), which
            this instruction refers to."""
            session.current().labels.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            """The next instruction, two bytes on."""
            return [binary_loc.binary_addr + 2]

        def instruction(self, binary_addr):
            """The instruction, with its operand as a label, expression or
            number (see classification.get_address8())."""
            # (A label used here must be defined before this instruction, or
            # the assembler would take it to be an absolute address: see
            # disassembly.define_forward_zero_page_labels_first())
            address_string = classification.get_address8(binary_addr + 1)
            return output.Instruction(self.mnemonic, address_string, prefix=self.prefix, suffix=self.suffix)


    class OpcodeAbs(Opcode):
        """An instruction with an absolute address as its operand (two
        bytes): the base class of OpcodeDataAbs, OpcodeJmpAbs, OpcodeJmpInd
        and OpcodeJsr. has_zp_version says whether there's a zero page
        version of the instruction, which an assembler would choose for an
        operand below $100 (see instruction())."""

        def __init__(self, instruction_template, reg_change, has_zp_version=True, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, cycles=cycles, update=update)
            self._has_zp_version = has_zp_version

        def abs_operand(self, binary_addr):
            """The operand: an address, as a runtime address."""
            return memorymanager.RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def target(self, binary_addr):
            """The operand's address."""
            return memorymanager.RuntimeAddr(self.abs_operand(binary_addr))

        def has_zp_version(self):
            """Whether there's a zero page version of the instruction."""
            return self._has_zp_version

        def instruction(self, binary_addr):
            """The instruction, with its operand as a label, expression or
            number (see classification.get_address16()), written so that it
            assembles to this opcode even if the operand is below $100: with
            the assembler's way of forcing absolute addressing, or else as
            data, with the instruction in a comment."""
            # We need to avoid misassembly of absolute instructions with zero-page
            # operands. (These are relatively rare in real code, but apart from the
            # fact we should still handle them even if they're rare, they can also
            # happen when the disassembly is imperfect and data is interpreted as
            # code. If we don't cope with them, bytes get lost and the disassembly
            # can't be correctly reassembled into a binary matching the input.)

            # (An expression for the operand must have the operand's value: see
            # classification.check_expr(). So the value decides it.)
            operand = classification.get_address16(binary_addr + 1)
            if not self.has_zp_version() or memorymanager.get_u16_binary(binary_addr + 1) >= 0x100:
                return output.Instruction(self.mnemonic, operand, prefix=self.prefix, suffix=self.suffix)

            # This is an absolute instruction with a zero-page operand which could
            # be misassembled. If the assembler has a way to explicitly request
            # absolute addressing, we use that.
            if config.get_assembler().can_force_absolute():
                return output.Instruction(self.mnemonic, operand, prefix=self.prefix, suffix=self.suffix, form=output.Instruction.FORCE_ABSOLUTE)

            # This assembler has no way to force absolute addressing, so emit the
            # instruction as data with a comment showing what it is.
            return output.Instruction(self.mnemonic, operand, prefix=self.prefix, suffix=self.suffix, form=output.Instruction.AS_DATA,
                                      data_byte=classification.get_constant8(binary_addr), listing_operand=operand)


    class OpcodeDataAbs(OpcodeAbs):
        """An instruction that reads or writes memory at an absolute address
        (e.g. LDA addr,X or INC addr), rather than going there."""

        def __init__(self, instruction_template, reg_change, has_zp_version=True, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, has_zp_version, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            """The operand's address gets a label (if it hasn't one), which
            this instruction refers to."""
            ref = self.abs_operand(binary_loc.binary_addr)
            session.current().labels.labels[ref].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            """The next instruction, three bytes on."""
            return [binary_loc.binary_addr + 3]


    class OpcodeJmpAbs(OpcodeAbs):
        """JMP addr: the code goes on at the target, not at the next
        instruction. It has no update function, so nothing is known after
        it. (A JMP to a subroutine counts as a call to it: see
        find_subroutine_calls().)"""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def update_references(self, binary_loc):
            """The target gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            """True: the code doesn't run on."""
            return True

        def could_be_call_to_subroutine(self):
            """True: the target could be a subroutine (a tail call)."""
            return True

        def disassemble(self, binary_loc):
            """The target (see Cpu.jump_target()), and no next instruction."""
            # Get the destination location of the JMP
            return [None] + session.current().cpu.jump_target(self.target(binary_loc.binary_addr), binary_loc)


    class OpcodeJmpInd(OpcodeAbs):
        """JMP (addr): a jump to the address stored at addr (the vector).
        That isn't known until the code runs, so tracing stops here (the
        code it goes to can be given with entry(), or with code_ptr() on
        the vector, if that's in the binary). The vector gets a label."""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def abs_operand(self, binary_addr):
            """The vector's address."""
            return memorymanager.RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def update_references(self, binary_loc):
            """The vector gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            """True: the code doesn't run on."""
            return True

        def is_unconditional_branch(self):
            """True: the code goes elsewhere."""
            return True

        def disassemble(self, binary_loc):
            """Nothing more to trace from here."""
            return [None]


    class OpcodeJsr(OpcodeAbs):
        """JSR addr: the subroutine at the target is traced, and so is the
        code after the JSR, where the subroutine returns to, unless a
        subroutine hook says otherwise (see disassemble()). It has no update
        function, so nothing is known after it (the subroutine could change
        anything)."""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def update_references(self, binary_loc):
            """The target gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def could_be_call_to_subroutine(self):
            """True: it's a call."""
            return True

        def is_unconditional_branch(self):
            """True: the code goes to the subroutine first."""
            return True

        def disassemble(self, binary_loc):
            """Where the subroutine returns to (or None), then the target (see
            Cpu.jump_target()).

            Where it returns to is the next instruction, unless the target
            has a subroutine hook (see hook_subroutine()). The hook is called
            in the JSR's move, so its commands (e.g. stringz() for a string
            after the JSR) work on the right copy of the code. It returns the
            runtime address the code goes on at, or None if the subroutine
            doesn't return (or if it adds the entry points itself, with
            entry())."""
            assert isinstance(binary_loc.binary_addr, memorymanager.BinaryAddr)

            # Get the destination location of the JSR
            target_runtime_addr = self.target(binary_loc.binary_addr)
            target_binary_addrs = session.current().cpu.jump_target(target_runtime_addr, binary_loc)

            # A hook only gets to return the "straight line" address to continue
            # tracing from (if there is one; it can return None if it wishes). Some
            # subroutines (e.g. jsr is_yx_zero:equw target_if_true, target_if_false)
            # might have no "straight line" case and want to return some labelled
            # entry points. This is supported by having the hook simply return None
            # and call entry() itself for the labelled entry points.

            def simple_subroutine_hook(target_runtime_addr, caller_runtime_addr):
                """The hook for a subroutine without one: it returns to the
                instruction after the JSR."""
                assert isinstance(target_runtime_addr, memorymanager.RuntimeAddr)
                assert isinstance(caller_runtime_addr, memorymanager.RuntimeAddr)

                return caller_runtime_addr + 3

            subroutine_hook = session.current().cpu.subroutine_hooks.get(target_runtime_addr, simple_subroutine_hook)
            caller_runtime_addr = movemanager.b2r(binary_loc.binary_addr)

            with session.current().moves.move_id_for_binary_addr[binary_loc.binary_addr]:
                return_runtime_addr = subroutine_hook(target_runtime_addr, caller_runtime_addr)

            if return_runtime_addr is not None:
                return_runtime_addr = memorymanager.RuntimeAddr(return_runtime_addr)
                result = session.current().cpu.get_target_binary_addr_preferring_given_move_id(return_runtime_addr, binary_loc.move_id)
                if len(result) == 0:
                    # The return runtime address could not be unambiguously converted into a binary
                    # address. It's highly likely the JSR is returning to the immediately following
                    # instruction, so if binary_addr+3 maps to the return runtime address, use that,
                    # otherwise give up and don't trace anything "after" the JSR.
                    simple_return_binary_addr = binary_loc.binary_addr + 3
                    if simple_return_binary_addr < 0x10000 and return_runtime_addr == movemanager.b2r(simple_return_binary_addr):
                        result = [simple_return_binary_addr]
                    else:
                        result = [None]
            else:
                result = [None]
            return result + target_binary_addrs


    class OpcodeConditionalBranch(Opcode):
        """A conditional branch (BPL, BMI, BVC, BVS, BCC, BCS, BNE or BEQ):
        both the next instruction and the target are traced. Its update
        function (from make_branch()) sets the flag for the branch not being
        taken, since the CPU state goes on to the next instruction."""

        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super().__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def target(self, binary_addr):
            """The target's runtime address."""
            # (Like the 6502, wrapping round the top or bottom of memory)
            return memorymanager.RuntimeAddr(branch_target(binary_addr) & 0xffff)

        def abs_operand(self, binary_addr):
            """The target's runtime address."""
            return self.target(binary_addr)

        def update_references(self, binary_loc):
            """The target gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            """The next instruction, and the target, in the branch's own move
            if it has one there (see Cpu.jump_target())."""
            return [binary_loc.binary_addr + 2] + session.current().cpu.jump_target(self.target(binary_loc.binary_addr), binary_loc, prefer_own_move=True)

        def could_be_call_to_subroutine(self):
            """True: the target could be a subroutine (a tail call)."""
            return True

        def update_cpu_state(self, binary_addr, state):
            """Change 'state' for the branch (see Opcode.update_cpu_state()).

            If the flag is known for certain to make it branch, it's always
            taken ('ALWAYS branch'), and nothing is known after it. A branch
            to the next instruction says nothing. Otherwise the branch is
            taken not to have been taken, so its flag (and what follows from
            that: see CpuStateDisposition.update_transfer()) is known
            after it."""
            # if there's a label at this address, then we lose all known pessimistic state.
            # This is because somewhere will be jumping to the label with unknown state.
            self.clear_pessimistic_state_if_label_here(binary_addr, state)

            # Work out if ALWAYS branch is appropriate
            always_branch = False
            # if the state of the flag is known and will cause the instruction to branch, then 'ALWAYS branch' is output
            if self.mnemonic.upper() == "BCC" and state.pessimistic['c'] == False:
                always_branch = True
            elif self.mnemonic.upper() == "BCS" and state.pessimistic['c'] == True:
                always_branch = True
            elif self.mnemonic.upper() == "BVC" and state.pessimistic['v'] == False:
                always_branch = True
            elif self.mnemonic.upper() == "BVS" and state.pessimistic['v'] == True:
                always_branch = True
            elif self.mnemonic.upper() == "BNE" and state.pessimistic['z'] == False:
                always_branch = True
            elif self.mnemonic.upper() == "BEQ" and state.pessimistic['z'] == True:
                always_branch = True
            elif self.mnemonic.upper() == "BPL" and state.pessimistic['n'] == False:
                always_branch = True
            elif self.mnemonic.upper() == "BMI" and state.pessimistic['n'] == True:
                always_branch = True

            if always_branch:
                # Branch is always taken, so known state is cleared, and always_branch flag is set.
                state.clear(pessimistic_only=False)
                state.always_branch = True
            elif self.target(BinaryAddr(binary_addr)) == (movemanager.b2r(BinaryAddr(binary_addr)) + 2) & 0xffff:
                # A branch to the next instruction says nothing about its
                # condition (whether it's taken or not, the code continues
                # there)
                state.always_branch = False
            else:
                # Assume conditional branch is not taken, we continue tracing
                if self.update is not None:
                    self.regular_update(binary_addr, state)
                    self.update(binary_addr, state)
                else:
                    state.clear(pessimistic_only=False)

        def instruction(self, binary_addr):
            """The instruction, with the target's label (see
            branch_operand())."""
            return branch_operand(self.mnemonic, binary_addr, self.target(binary_addr))


    # ********************************************************************************************
    # The update functions for the opcode table: each is called as
    # update(binary address of the instruction, CpuState), after
    # Opcode.regular_update(), and changes both versions of the state

    def make_update_flag(self, flag, b):
        """An update function that sets 'flag' to b (e.g. CLC, SEI)."""
        def update_flag(addr, state):
            state.optimistic[flag] = b
            state.pessimistic[flag] = b
        return update_flag

    def make_decrement(self, reg):
        """An update function that decrements 'reg' (e.g. DEX: see
        CpuStateDisposition.decrement())."""
        def decrement(addr, state):
            state.pessimistic.decrement(addr, reg)
            state.optimistic.decrement(addr, reg)
        return decrement

    def make_increment(self, reg):
        """An update function that increments 'reg' (e.g. INX)."""
        def increment(addr, state):
            state.optimistic.increment(addr, reg)
            state.pessimistic.increment(addr, reg)
        return increment

    def make_load_immediate(self, reg):
        """An update function that loads 'reg' with the instruction's
        operand (e.g. LDA #imm)."""
        # (The session's memory is looked up once, when the opcode table is
        # made)
        memory_binary = session.current().memory.binary
        def load_immediate(addr, state):
            v = memory_binary[addr+1]
            state.optimistic.load_immediate(addr, reg, v)
            state.pessimistic.load_immediate(addr, reg, v)
        return load_immediate

    def make_transfer(self, src_reg, dest_reg):
        """An update function that copies src_reg to dest_reg (e.g. TAX)."""
        def transfer(addr, state):
            state.optimistic.transfer(addr, src_reg, dest_reg)
            state.pessimistic.transfer(addr, src_reg, dest_reg)
        return transfer

    def make_branch(self, flag, flag_state):
        """An update function for a conditional branch on 'flag', which
        branches unless the flag is flag_state (e.g. for BNE, 'z' and True:
        see CpuStateDisposition.update_transfer())."""
        # If a flag state is not currently known, this sets the flag state *assuming the branch is
        # NOT taken*. e.g. if "BNE addr" then we set the Z flag assuming the branch is not taken
        # i.e. Z=1
        # This lets us continue tracing with appropriate state from the next instruction after
        # the branch.

        # This also helps detect a pair of opposite conditional branches, marking 'ALWAYS branch':
        #    BNE addr1
        #    BEQ addr2              ; ALWAYS branch
        def update_branch(addr, state):
            state.optimistic.update_transfer(addr, flag, flag_state)
            state.pessimistic.update_transfer(addr, flag, flag_state)

        return update_branch

    def neutral(self, binary_addr, state):
        """No flags or values change (e.g. STA, PHA, NOP)."""
        assert binary_addr is not None
        pass

    def update_clear_nz(self, binary_addr, state):
        """N and Z become unknown (e.g. LDA from memory, PLA, INC memory)."""
        assert binary_addr is not None
        state.optimistic.update_clear_nz(binary_addr)
        state.pessimistic.update_clear_nz(binary_addr)

    def update_clear_nza(self, binary_addr, state):
        """N, Z and A become unknown (e.g. ORA, AND and EOR from memory)."""
        assert binary_addr is not None
        state.optimistic.update_clear_nza(binary_addr)
        state.pessimistic.update_clear_nza(binary_addr)

    def update_clear_nzc(self, binary_addr, state):
        """N, Z and C become unknown (shifts and rotates of memory)."""
        assert binary_addr is not None
        state.optimistic.update_clear_nzc(binary_addr)
        state.pessimistic.update_clear_nzc(binary_addr)

    def update_clear_nzca(self, binary_addr, state):
        """N, Z, C and A become unknown (e.g. ASL A)."""
        assert binary_addr is not None
        state.optimistic.update_clear_nzca(binary_addr)
        state.pessimistic.update_clear_nzca(binary_addr)

    def update_compare(self, binary_addr, state):
        """A compare (CMP, CPX, CPY): N becomes unknown, and Z and C
        'pending'."""
        assert binary_addr is not None
        state.optimistic.update_clear_nz_pending_c(binary_addr)
        state.pessimistic.update_clear_nz_pending_c(binary_addr)

    def update_rora(self, binary_addr, state):
        """ROR A (see CpuStateDisposition.update_rora())."""
        assert binary_addr is not None
        state.optimistic.update_rora(binary_addr)
        state.pessimistic.update_rora(binary_addr)

    def update_bit(self, binary_addr, state):
        """BIT: N, V and Z become unknown."""
        assert binary_addr is not None
        state.optimistic.update_bit(binary_addr)
        state.pessimistic.update_bit(binary_addr)

    def update_adc_sbc(self, binary_addr, state):
        """ADC or SBC: A, N, V, Z and C become unknown."""
        assert binary_addr is not None
        state.optimistic.update_adc_sbc(binary_addr)
        state.pessimistic.update_adc_sbc(binary_addr)

    def update_all_flags(self, binary_addr, state):
        """PLP: all the flags become unknown."""
        assert binary_addr is not None
        state.optimistic.update_all_flags(binary_addr)
        state.pessimistic.update_all_flags(binary_addr)

    def update_AND_immediate(self, binary_addr, state):
        """AND #imm (see CpuStateDisposition.update_AND_immediate())."""
        assert binary_addr is not None
        state.optimistic.update_AND_immediate(binary_addr)
        state.pessimistic.update_AND_immediate(binary_addr)

    def update_ORA_immediate(self, binary_addr, state):
        """ORA #imm (see CpuStateDisposition.update_ORA_immediate())."""
        assert binary_addr is not None
        state.optimistic.update_ORA_immediate(binary_addr)
        state.pessimistic.update_ORA_immediate(binary_addr)

    # ********************************************************************************************
    # Analysis of the traced code

    def is_subroutine_call(self, binary_addr):
        """Whether the instruction at binary_addr is a JSR. (A label that
        only JSRs refer to is named 'sub_...': see
        disassembly.suggest_label_name().)"""
        assert binary_addr is not None
        c = classification.get_classification(binary_addr)
        result = isinstance(c, self.Opcode) and c.mnemonic == "JSR"
        return result

    def is_branch_to(self, binary_addr, target_runtime_addr):
        """Whether the instruction at binary_addr is a branch or JMP to
        target_runtime_addr. (A label that one backward branch refers to is
        named 'loop_...': see disassembly.suggest_label_name().)"""
        assert binary_addr is not None

        c = classification.get_classification(binary_addr)

        if isinstance(c, self.OpcodeConditionalBranch):
            return c.target(binary_addr) == target_runtime_addr
        if isinstance(c, self.OpcodeJmpAbs):
            return memorymanager.get_u16_binary(binary_addr + 1) == target_runtime_addr
        return False

    # Note that this does *not* check for labels breaking up a
    # sequence. We're not optimising code here, we are making an
    # inference from a series of straight line instructions - the fact
    # that the sequence might *also* be entered part-way through via a
    # label doesn't invalidate that inference.
    def subroutine_argument_finder(self):
        """Call each of the hooks in trace.subroutine_argument_finder_hooks
        for each JSR or JMP, with the target (a runtime address) and, for
        each of A, X and Y, the binary address of the immediate operand it
        was loaded from (e.g. the 'nn' of 'ldx #nn', so the hook can give it
        an expression), or None, from the optimistic state, until one
        returns something other than None. There's no command for these
        hooks: a control file can append them to the list (which older
        control files may do), and none do in the examples."""
        memory_binary = session.current().memory.binary
        if len(session.current().trace.subroutine_argument_finder_hooks) == 0:
            return

        binary_addr = 0
        state = None
        # (Only the loaded data can be classified, so just loop over that)
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = max(binary_addr, range_start)
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is not None:
                    if state is None:
                        state = self.EMPTY_STATE

                    if isinstance(c, self.Opcode):
                        opcode = memory_binary[binary_addr]
                        if opcode in (OPCODE_JSR, OPCODE_JMP):
                            target = memorymanager.get_u16_binary(binary_addr + 1)
                            for hook in session.current().trace.subroutine_argument_finder_hooks:
                                if hook(memorymanager.RuntimeAddr(target),
                                    state.optimistic['a'].get_previous_load_imm_operand(),
                                    state.optimistic['x'].get_previous_load_imm_operand(),
                                    state.optimistic['y'].get_previous_load_imm_operand()) is not None:
                                    break
                    state = self.cpu_states[binary_addr]
                    binary_addr += c.length()
                else:
                    binary_addr += 1

    def scan_ahead_for_post_exit_state(self, binary_addr, state):
        """Find where the code after the JSR at binary_addr first uses each
        register, for a subroutine's hook (so a comment can say what the
        subroutine returned in it). Sets state.next_use to {'a', 'x', 'y':
        the binary address of that instruction, or None} and
        state.next_instruction to the binary address after the JSR.

        Each register's search stops at the first instruction that does
        anything with it: if that only uses it (e.g. STA, CMP, TAX), that's
        its next use; if it changes it (even after reading it, e.g. AND or
        INX), there's none. The whole search stops at the end of the
        straight line code: anything that isn't an instruction, the end of
        a block, or a JSR, JMP (addr) or BRA after the first instruction."""
        assert binary_addr is not None
        scanning_for_register_usage = {'a': True, 'x': True, 'y': True }

        state.next_instruction = None
        state.next_use = {'a': None, 'x': None, 'y': None }

        newstate = self.cpu_states[binary_addr]    # State after the JSR

        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)

            # Must be classified
            if c is None:
                return

            # Stop at an address that wasn't traced as an instruction
            if binary_addr not in self.traced_entry_points:
                return

            # Stop at the end of a code block
            if not c.is_code(binary_addr) or c.is_block_end():
                return

            # Must have known state
            if newstate is None:
                return

            # Must be an opcode
            if not isinstance(c, self.Opcode):
                return

            if state.next_instruction is not None:
                # Beyond the first instruction (the call to the subroutine), a JSR/BRA is enough to end any register use knowledge
                if c.is_unconditional_branch():
                    return

            for reg in scanning_for_register_usage:
                if scanning_for_register_usage[reg]:
                    if c.reg_changes[reg] == 'U':
                        state.next_use[reg] = binary_addr

                    if c.reg_changes[reg] != '-':
                        scanning_for_register_usage[reg] = False
                        if not any(scanning_for_register_usage.values()):
                            return

            binary_addr += c.length()                               # Move to next instruction
            if state.next_instruction is None:
                state.next_instruction = binary_addr                # Set to the instruction address following the JSR
            newstate = self.cpu_states[binary_addr]            # State after instruction at addr has executed

    def show_register_knowledge(self):
        """Adds comments to show any known state of the processor (what's
        known for certain, from the pessimistic state): e.g. 'Y=1' on an
        instruction that changes a register to a known value (e.g. INY,
        TAX), 'Carry is set, so adding 6' or '+1 because carry is set' on an
        ADC (and the same for an SBC with carry clear), and 'ALWAYS branch'
        on a conditional branch that's always taken (with a blank line
        after it)."""
        binary_addr = 0
        prev_state = self.EMPTY_STATE
        state = self.EMPTY_STATE

        # (Only the loaded data can be classified, so just loop over that)
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = max(binary_addr, range_start)
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is not None:
                    prev_state = state
                    state = self.cpu_states[binary_addr]

                    # If there's a label here, then clear our prev_state (i.e. be pessimistic for this state)
                    runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
                    if runtime_addr is not None:
                        if runtime_addr in session.current().labels.labels:
                            prev_state = self.EMPTY_STATE

                    # Show the value of a register as an inline comment (if known) once they have been
                    # altered (e.g. for 'LDY #0:LDA (zp),Y:STA mem:INY' output '; Y=1' on the 'INY' line).

                    for reg in ['a', 'x', 'y']:
                        # If we know about the state of the register 'reg'
                        if state and state.pessimistic[reg]:
                            # If this instruction alters the register 'reg'
                            if c.reg_changes and ((c.reg_changes[reg] == 'A') or (c.reg_changes[reg] == 'T')):
                                # Get the value of the register
                                r = state.pessimistic[reg].value
                                if r is not None:
                                    move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                                    binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                                    formatter = config.get_assembler()
                                    if r > 9:
                                        r = formatter.hex(r)
                                    disassembly.comment_binary(binary_loc, "{0}={1}".format(reg.upper(), r), align=Align.INLINE, auto_generated=True)

                    # Check for ADC or SBC with carry in its opposite to normal state: auto comment it
                    if isinstance(c, self.Opcode):
                        value = memorymanager.get_u8_binary(binary_addr)
                        if prev_state and prev_state.pessimistic['c'] == True:
                            move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                            binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                            if value == OPCODE_ADC_IMMEDIATE:
                                value = memorymanager.get_u8_binary(binary_addr+1)
                                disassembly.comment_binary(binary_loc, "Carry is set, so adding {0}".format((value + 1) & 255), align=Align.INLINE, auto_generated=True)
                            elif (value == OPCODE_ADC_INDEXED_INDIRECT) or (value == OPCODE_ADC_ZERO_PAGE) or (value == OPCODE_ADC_ABSOLUTE) or (value == OPCODE_ADC_INDIRECT_INDEXED) or (value == OPCODE_ADC_ZERO_PAGE_COMMA_X) or (value == OPCODE_ADC_ABSOLUTE_COMMA_Y) or (value == OPCODE_ADC_ABSOLUTE_COMMA_X):
                                disassembly.comment_binary(binary_loc, "+1 because carry is set", align=Align.INLINE, auto_generated=True)

                        elif prev_state and prev_state.pessimistic['c'] == False:
                            move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                            binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                            if value == OPCODE_SBC_IMMEDIATE:
                                value = memorymanager.get_u8_binary(binary_addr+1)
                                disassembly.comment_binary(binary_loc, "Carry is clear, so subtracting {0}".format((value + 1) & 255), align=Align.INLINE, auto_generated=True)
                            elif (value == OPCODE_SBC_INDEXED_INDIRECT) or (value == OPCODE_SBC_ZERO_PAGE) or (value == OPCODE_SBC_ABSOLUTE) or (value == OPCODE_SBC_INDIRECT_INDEXED) or (value == OPCODE_SBC_ZERO_PAGE_COMMA_X) or (value == OPCODE_SBC_ABSOLUTE_COMMA_Y) or (value == OPCODE_SBC_ABSOLUTE_COMMA_X):
                                disassembly.comment_binary(binary_loc, "-1 because carry is clear", align=Align.INLINE, auto_generated=True)

                    # Find "ALWAYS branch" instructions
                    if isinstance(c, self.OpcodeConditionalBranch):
                        if state.always_branch:
                            move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                            binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                            disassembly.comment_binary(binary_loc, "ALWAYS branch", align=Align.INLINE, auto_generated=True)
                            disassembly.add_raw_annotation(binary_loc, "", align=Align.AFTER_LINE)  # add a blank line after ALWAYS branch
                    binary_addr += c.length()
                else:
                    binary_addr += 1
                    prev_state = self.EMPTY_STATE


    def find_subroutine_calls(self):
        """Finds calls to subroutines, and calls its hook function.

        Subroutines will have been registered previously with calls
        to the subroutine() command.

        A call is a JSR, JMP or branch to the subroutine's address. The
        hook is also called for the instruction at the subroutine's own
        address, since code may run on into it from the instruction before.

        The hook function receives the address, CPU state, and
        subroutine data and most likely uses it to label and/or comment
        the calling code. (The address is the runtime address of the call,
        or of the subroutine; the state is the one before that instruction.
        For a JSR, the state's next_use says where the code after it uses
        each register: see scan_ahead_for_post_exit_state().)
        """

        binary_addr = 0
        state = None

        # The binary address of each subroutine, by runtime address (cached,
        # since otherwise it's worked out for every instruction)
        sub_binary_addrs = {}

        # (Only the loaded data can be classified, so just loop over that)
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = max(binary_addr, range_start)
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is not None:
                    if state is None:
                        state = self.EMPTY_STATE

                    if isinstance(c, self.Opcode):
                        could_be_call_to_subroutine = c.could_be_call_to_subroutine()
                        binary_addr = memorymanager.BinaryAddr(binary_addr)
                        target = c.target(binary_addr)

                        # check each subroutine
                        for subroutine in session.current().trace.subroutines_list:
                            if subroutine.hook_function is None:
                                continue

                            found = False
                            fall_through = False

                            # convert to binary address
                            if subroutine.runtime_addr not in sub_binary_addrs:
                                sub_binary_addrs[subroutine.runtime_addr], _ = movemanager.r2b(subroutine.runtime_addr)
                            sub_binary_addr = sub_binary_addrs[subroutine.runtime_addr]
                            if binary_addr == sub_binary_addr:
                                # We are at the subroutine address itself.
                                # We might have fallen through from above
                                # and so we count this as a match.
                                found = True
                                fall_through = True
                            elif could_be_call_to_subroutine and (target == subroutine.runtime_addr):
                                # If our instruction is a call to the
                                # address of the subroutine, then we have
                                # found a match.
                                found = True

                            if found:
                                state.next_instruction = None
                                state.next_use = {'a': None, 'x': None, 'y': None }

                                runtime_addr = movemanager.b2r(binary_addr)
                                if not fall_through and isinstance(c, self.OpcodeJsr):
                                    self.scan_ahead_for_post_exit_state(binary_addr, state)
                                subroutine.hook_function(runtime_addr, state, subroutine)

                    state = self.cpu_states[binary_addr]
                    binary_addr += c.length()
                else:
                    binary_addr += 1
                    state = self.EMPTY_STATE

    def substitute_constants(self):
        """Name the immediate values loaded into registers before the
        instructions given with substitute_constants() (each a SubConst in
        trace.substitute_constant_list).

        For each instruction that matches one (its opcode, and its operand's
        address and condition, if it has them), where the register's value
        is known and it was loaded with an immediate value (e.g. 'lda #5',
        or 'lda #5 : tax' for X), that operand is given the name or
        expression the SubConst's dictionary has for the value (if it has
        one), which is defined as a constant if the SubConst says so. This
        uses the optimistic state, so a label between the load and the
        instruction doesn't stop it."""
        memory_binary = session.current().memory.binary
        if len(session.current().trace.substitute_constant_list) == 0:
            return

        binary_addr = 0
        state = None

        # (Only the loaded data can be classified, so just loop over that)
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = max(binary_addr, range_start)
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is None:
                    binary_addr += 1
                    continue

                if state is None:
                    state = self.EMPTY_STATE

                if isinstance(c, self.Opcode):
                    opcode = memory_binary[binary_addr]

                    # for each const_sub
                    for const_sub in session.current().trace.substitute_constant_list:
                        # check we have the right opcode
                        if opcode != const_sub.get_opcode(self.opcodes):
                            continue

                        # make sure we know the current value of the appropriate register
                        reg_value = state.optimistic[const_sub.reg].value
                        if reg_value is None:
                            continue

                        # check that we know where the register was set
                        where_reg_set = state.optimistic[const_sub.reg].get_previous_load_imm_operand()
                        if where_reg_set is None:
                            continue

                        # if we have an operand, make sure it matches too
                        if const_sub.operand and (const_sub.get_operand_value() != c.target(binary_addr)):
                            continue

                        if const_sub.condition is not None and not const_sub.condition(binary_addr):
                            continue

                        # check the const_sub dictionary has the current value as a key
                        if not reg_value in const_sub.constants_dict:
                            continue

                        # set the constant or expression at this address
                        const_or_expression = const_sub.constants_dict[reg_value]
                        classification.add_expression(where_reg_set, const_or_expression)

                        # define the constant, if desired
                        if const_sub.define_constant:
                            # is this a constant?
                            if disassembly.is_simple_name(const_or_expression):
                                # define the constant
                                disassembly.add_constant(reg_value, const_or_expression)

                state = self.cpu_states[binary_addr]
                binary_addr += c.length()

    def label_maker(self, lmd):
        """Name an auto-generated label on an RTS 'return_1', 'return_2' and
        so on (each RTS gets the next number the first time it's named), if
        config.get_label_return_instructions_numerically()."""
        # Label return_1, return_2 etc
        memory_binary = session.current().memory.binary
        if config.get_label_return_instructions_numerically():
            # Only if the current label is autogenerated
            if lmd.is_autogenerated:
                defined_at_binary_addr, _ = movemanager.r2b(lmd.defined_as_runtime_addr, lmd.defined_in_move_id)
                c = classification.get_classification(defined_at_binary_addr)
                if c is not None:
                    if isinstance(c, self.Opcode):
                        by = memory_binary[defined_at_binary_addr]
                        if by == OPCODE_RTS:
                            if not defined_at_binary_addr in self.return_array:
                                self.return_index += 1
                                self.return_array[defined_at_binary_addr] = self.return_index

                            lmd.name = "return_{0}".format(self.return_array[defined_at_binary_addr])

    # ********************************************************************************************
    # What the code does: straight runs of code, and the memory they write

    # The instructions that store a register, with the register (SAX, the
    # 6510's, stores A AND X; STZ, the 65C02's, stores zero)
    _STORE_MNEMONICS = {"STA": 'a', "STX": 'x', "STY": 'y', "STZ": None, "SAX": None}

    # The instructions that write memory after reading it, or that write an
    # unknown value (the 6510's SHA etc, which are always indexed)
    _READ_MODIFY_WRITE_MNEMONICS = {"ASL", "LSR", "ROL", "ROR", "INC", "DEC", "TSB", "TRB",
                                    "SLO", "RLA", "SRE", "RRA", "DCP", "ISC", "SHA", "SHX", "SHY", "TAS"}

    # ********************************************************************************************
    # Redundant instructions: those whose results are never used

    # The registers and flags (d is the decimal flag, i the interrupt flag)
    _ALL_RESOURCES = frozenset("axynvdizc")

    # The instructions that can be redundant: they only change registers and
    # flags (and read memory, which mustn't be I/O), as (reads, writes).
    # (ASL, LSR, ROL, ROR, INC and DEC only with A as the operand.)
    _REDUNDANT_CANDIDATES = {
        "lda": ("", "anz"), "ldx": ("", "xnz"), "ldy": ("", "ynz"),
        "tax": ("a", "xnz"), "tay": ("a", "ynz"), "txa": ("x", "anz"), "tya": ("y", "anz"), "tsx": ("", "xnz"),
        "inx": ("x", "xnz"), "dex": ("x", "xnz"), "iny": ("y", "ynz"), "dey": ("y", "ynz"),
        "adc": ("acd", "anvzc"), "sbc": ("acd", "anvzc"),
        "and": ("a", "anz"), "ora": ("a", "anz"), "eor": ("a", "anz"),
        "cmp": ("a", "nzc"), "cpx": ("x", "nzc"), "cpy": ("y", "nzc"), "bit": ("a", "nvz"),
        "asl": ("a", "anzc"), "lsr": ("a", "anzc"), "rol": ("ac", "anzc"), "ror": ("ac", "anzc"),
        "inc": ("a", "anz"), "dec": ("a", "anz"),
        "clc": ("", "c"), "sec": ("", "c"), "clv": ("", "v"),
    }
    _ACCUMULATOR_ONLY = {"asl", "lsr", "rol", "ror", "inc", "dec"}

    # The other instructions that don't change the flow of control (which
    # aren't redundant, since they have other effects), as (reads, writes).
    # (Any other instruction is taken to read everything: e.g. JSR, whose
    # subroutine could use anything, or a branch, whose target could.)
    _OTHER_INSTRUCTIONS = {
        "sta": ("a", ""), "stx": ("x", ""), "sty": ("y", ""), "stz": ("", ""),
        "pha": ("a", ""), "phx": ("x", ""), "phy": ("y", ""), "php": ("nvdizc", ""),
        "pla": ("", "anz"), "plx": ("", "xnz"), "ply": ("", "ynz"), "plp": ("", "nvdizc"),
        "txs": ("x", ""), "nop": ("", ""),
        "cli": ("", "i"), "sei": ("", "i"), "cld": ("", "d"), "sed": ("", "d"),
        "asl": ("", "nzc"), "lsr": ("", "nzc"), "rol": ("c", "nzc"), "ror": ("c", "nzc"),
        "inc": ("", "nz"), "dec": ("", "nz"), "trb": ("a", "z"), "tsb": ("a", "z"),
    }

    def _memory_operand_range(self, c, binary_addr):
        """The runtime addresses the instruction might read or write (first,
        last), or None if it doesn't use memory, or 'unknown' for an indirect
        operand."""
        memory_binary = session.current().memory.binary
        mode = c.addr_mode
        if mode in (self.mode_implied, self.mode_immediate, self.mode_accumulator, self.mode_offset):
            return None
        if mode in (self.mode_indexed_indirect, self.mode_indirect_indexed, self.mode_indirect_zp, self.mode_indirect_addr, self.mode_indexed_abs):
            return "unknown"
        if mode in (self.mode_zp, self.mode_zp_indexed_x, self.mode_zp_indexed_y):
            base = memory_binary[binary_addr + 1]
            return (base, base) if mode == self.mode_zp else (0, 0xff)
        base = memorymanager.get_u16_binary(binary_addr + 1)
        if mode == self.mode_addr:
            return (base, base)
        return (base, base + 0xff)

    def _instruction_effects(self, c, binary_addr):
        """What the instruction does to the registers and flags, for
        find_redundant_instructions(): (reads, writes, whether it could be
        redundant), with reads and writes as sets of 'axynvdizc'. An index
        register counts as read.

        One of _REDUNDANT_CANDIDATES could be redundant, unless it reads I/O
        (see io_range()) or an address that isn't known (an indirect
        operand). Anything that isn't one of those or of
        _OTHER_INSTRUCTIONS (e.g. a JSR, a branch, or the end of a block)
        reads everything and writes nothing."""
        mnemonic = c.mnemonic.lower()
        mode = c.addr_mode
        index = {self.mode_indexed_indirect: "x", self.mode_abs_indexed_x: "x", self.mode_zp_indexed_x: "x",
                 self.mode_indirect_indexed: "y", self.mode_abs_indexed_y: "y", self.mode_zp_indexed_y: "y"}.get(mode, "")
        accumulator = mode in (self.mode_accumulator, self.mode_implied)
        if mnemonic in self._REDUNDANT_CANDIDATES and (accumulator or mnemonic not in self._ACCUMULATOR_ONLY):
            reads, writes = self._REDUNDANT_CANDIDATES[mnemonic]
            if mnemonic == "bit" and mode == self.mode_immediate:
                writes = "z"                    # (The 65C02's BIT #n only sets Z)
            # Reading I/O has side effects (e.g. acknowledging an interrupt)
            memory = self._memory_operand_range(c, binary_addr)
            io_ranges = session.current().disassembly.io_ranges
            candidate = memory is None or (memory != "unknown" and not any(start <= memory[1] and memory[0] < end for start, end in io_ranges))
            return set(reads + index), set(writes), candidate
        if mnemonic in self._OTHER_INSTRUCTIONS and not c.is_block_end():
            reads, writes = self._OTHER_INSTRUCTIONS[mnemonic]
            return set(reads + index), set(writes), False
        return set(self._ALL_RESOURCES), set(), False

    def is_entered_inside(self, binary_addr, length):
        """Whether code can start in the middle of the instruction at
        binary_addr (with the given length): there's an explicit entry
        point there (e.g. from entry(): see add_entry()), or a jump, branch
        or call goes there, to a byte that is an opcode. E.g. the BIT trick:
        'bit $02a9' hides 'lda #2' (a9 02), which other code jumps to, and
        code that comes to the BIT skips it. (A reference to its operand
        from data, or from code that modifies it, doesn't count.)"""
        labels = session.current().labels.labels
        memory_binary = session.current().memory.binary
        for i in range(1, length):
            inside = BinaryAddr(binary_addr + i)
            if inside in self.explicit_entry_points:
                return True
            label = labels.get(movemanager.b2r(inside))
            if label is None or memory_binary[inside] not in self.opcodes:
                # (Code can't run from there if it isn't an instruction, e.g.
                # where a branch's offset is changed before it's used, so
                # its target as it's loaded doesn't matter)
                continue
            for ref in label.references:
                c = classification.get_classification(ref.binary_addr)
                if isinstance(c, self.Opcode) and c.could_be_call_to_subroutine() and c.target(ref.binary_addr) == movemanager.b2r(inside):
                    return True
        return False

    def find_redundant_instructions(self):
        """Comment each instruction whose results are never used: in a
        straight run of code (see straight_runs()), each register and flag
        it changes is changed again before anything reads it. E.g. 'lda
        foo' just before 'pla'. Only instructions that just change registers
        and flags (e.g. not a store, or a read of I/O, which can have side
        effects) can be redundant, and not one that code jumps into the
        middle of (the BIT trick). The end of a run, a JSR or a branch counts
        as reading everything. (See config.set_redundant_instruction_comments().)"""
        if not config.get_redundant_instruction_comments():
            return
        # Go backwards through each run, keeping the registers and flags
        # that something after the instruction might read ('live')
        for run in self.straight_runs():
            live = set(self._ALL_RESOURCES)
            for binary_addr in reversed(run):
                c = classification.get_classification(binary_addr)
                reads, writes, candidate = self._instruction_effects(c, binary_addr)
                if candidate and writes and not (writes & live) and not self.is_entered_inside(binary_addr, c.length()):
                    disassembly.comment_binary(BinaryAddr(binary_addr), "Redundant instruction?", align=Align.INLINE, word_wrap=False, auto_generated=True)
                    # (Its reads don't count, since it could be removed)
                    continue
                live = (live - writes) | reads

    def straight_runs(self):
        """The code, as runs of instructions (lists of binary addresses, in
        address order) that the code runs straight through: each ends at
        the end of a block (e.g. RTS or JMP), or before an instruction that
        other code jumps or branches to (or an entry point), since that might
        come from code with other values in its registers and memory. (A JSR
        doesn't end a run. Strictly, a run ends before any instruction
        whose label something refers to, e.g. code that modifies it.)"""
        labels = session.current().labels.labels
        explicit_entry_points = self.explicit_entry_points
        run = []
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = range_start
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is None or c is classification.INSIDE_A_CLASSIFICATION or not c.is_code(binary_addr):
                    if run:
                        yield run
                        run = []
                    binary_addr += 1 if c is None or c is classification.INSIDE_A_CLASSIFICATION else c.length()
                    continue
                label = labels.get(movemanager.b2r(BinaryAddr(binary_addr)))
                if run and ((label is not None and label.references) or binary_addr in explicit_entry_points):
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

    def memory_write(self, binary_addr):
        """The MemoryWrite for the instruction at binary_addr, if it writes
        memory (or might: a JSR, whose subroutine could write anywhere),
        otherwise None. A value is known only if it's known for certain
        (the pessimistic state)."""
        memory_binary = session.current().memory.binary
        c = classification.get_classification(binary_addr)
        if memory_binary[binary_addr] == 0x20:
            # JSR (see the docstring)
            return MemoryWrite(binary_addr, None)
        mnemonic = c.mnemonic.upper()
        is_store = mnemonic in self._STORE_MNEMONICS
        if not is_store and mnemonic not in self._READ_MODIFY_WRITE_MNEMONICS:
            return None
        if c.addr_mode == Cpu6502.mode_accumulator:
            return None
        if c.addr_mode == Cpu6502.mode_zp:
            target = memory_binary[binary_addr + 1]
        elif c.addr_mode == Cpu6502.mode_addr:
            target = memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]
        else:
            # Indexed or indirect: the address isn't known
            return MemoryWrite(binary_addr, None, read_modify_write=not is_store)
        if not is_store:
            return MemoryWrite(binary_addr, target, read_modify_write=True)
        state = self.cpu_states[binary_addr]
        pessimistic = None if state is None else state.pessimistic
        reg = self._STORE_MNEMONICS[mnemonic]
        if mnemonic == "STZ":
            return MemoryWrite(binary_addr, target, 0)
        if pessimistic is None:
            return MemoryWrite(binary_addr, target, reg=reg)
        if mnemonic == "SAX":
            a, x = pessimistic['a'].value, pessimistic['x'].value
            return MemoryWrite(binary_addr, target, None if a is None or x is None else a & x)
        # (A store doesn't change the register, so the state after it is
        # the state it stores)
        return MemoryWrite(binary_addr, target, pessimistic[reg].value, reg, pessimistic[reg].get_previous_load_imm_operand())

    def memory_writes(self, run):
        """The MemoryWrite for each instruction in the run (see
        straight_runs()) that writes memory, in order."""
        for binary_addr in run:
            write = self.memory_write(binary_addr)
            if write is not None:
                yield write

    # Regex searching (shared by the 6502, 6510 and 65C02)
    def pre_trace_with_regex(self):
        """Call the pre-trace function of each regex snippet (see
        snippets6502.py) for each of its matches in the loaded data, e.g. to
        add entry points for the code it recognises. A string in place of
        the function is an inline comment for the start of the match.

        The snippets are tried in order, and bytes one match covers aren't
        matched again. Each match's entry points are traced before the next
        match is looked at, so a match that turns out to start in the middle
        of an instruction can be rejected (SnippetRejected), and is then
        left for others to match, and ignored after tracing too (see
        rejected_snippet_matches). Effect patterns are left for
        find_entry_points_from_effects()."""
        # Make a byte array of memory
        memory_binary = session.current().memory.binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])
        loaded = memorymanager.loaded_ranges()

        # Remember which bytes are auto commented via a regex so we don't comment the same bytes again with a different regex.
        found_already = [False]*65536

        # for each snippet
        for index, details in enumerate(session.current().snippets):
            if details.pre_trace_function is None or getattr(details.pattern, "is_effect", False):
                continue

            # Find all matches (just in the loaded data)
            for match in (m for start, end in loaded for m in details.pattern.whole_pattern.finditer(bytes_array, start, end)):
                binary_addr = match.start()
                length = match.end() - match.start()

                # Check if any of the bytes are already commented on
                if any(found_already[binary_addr:binary_addr+length]):
                    continue

                move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                binary_loc = memorymanager.BinaryLocation(binary_addr, move_id)

                # Mark these bytes as True, already commented on
                found_already[binary_addr:binary_addr+length] = [True]*length
                helper = SnippetHelper(memory_binary, binary_loc, match, details.pattern.labels)
                if isinstance(details.pre_trace_function, str):
                    # A string means just add an inline comment
                    disassembly.comment_binary(helper.get_start_loc(), details.pre_trace_function, align=Align.INLINE, auto_generated=True)
                else:
                    try:
                        if details.pre_trace_parameter is None:
                            details.pre_trace_function(helper)
                        else:
                            details.pre_trace_function(helper, details.pre_trace_parameter)
                    except SnippetRejected:
                        # It starts in the middle of an instruction (or data),
                        # or the function rejected it, so the post trace
                        # function ignores it too, and other snippets can
                        # match its bytes
                        found_already[binary_addr:binary_addr+length] = [False]*length
                        self.rejected_snippet_matches.add((index, binary_addr))
                        continue

                # Trace from the match's entry points now, so the next match
                # is checked against the code they lead to
                self.trace_entry_points()

    def post_trace_with_regex(self):
        """Call the post-trace function of each regex snippet for each of its
        matches (except those rejected before tracing), once the code is
        traced and analysed, so it can use the CPU states (e.g. for comments
        and expressions). As before tracing, bytes one match covers aren't
        matched again. Then the same for the effect patterns
        (post_trace_effects())."""
        # Make a byte array of memory
        memory_binary = session.current().memory.binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])
        loaded = memorymanager.loaded_ranges()

        # Remember which bytes are auto commented via a regex so we don't comment the same bytes again with a different regex.
        found_already = [False]*65536

        # for each snippet
        for index, details in enumerate(session.current().snippets):
            if details.post_trace_function is None or getattr(details.pattern, "is_effect", False):
                continue

            # Find all matches (just in the loaded data)
            for match in (m for start, end in loaded for m in details.pattern.whole_pattern.finditer(bytes_array, start, end)):
                binary_addr = match.start()
                length = match.end() - match.start()

                # Ignore a match rejected before tracing
                if (index, binary_addr) in self.rejected_snippet_matches:
                    continue

                # Check if any of the bytes are already commented on
                if any(found_already[binary_addr:binary_addr+length]):
                    continue

                move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
                binary_loc = memorymanager.BinaryLocation(binary_addr, move_id)

                # Mark these bytes as True, already commented on
                found_already[binary_addr:binary_addr+length] = [True]*length
                helper = SnippetHelper(memory_binary, binary_loc, match, details.pattern.labels)

                if isinstance(details.post_trace_function, str):
                    # A string means just add an inline comment
                    disassembly.comment_binary(helper.get_start_loc(), details.post_trace_function, align=Align.INLINE, auto_generated=True)
                else:
                    if details.post_trace_parameter is None:
                        details.post_trace_function(helper)
                    else:
                        details.post_trace_function(helper, details.post_trace_parameter)


        # Then the effect patterns' matches, as last found (see
        # find_entry_points_from_effects())
        self.post_trace_effects()

    def find_entry_points_from_effects(self):
        """Find the matches of the effect patterns (see effectpattern.py),
        and call each new match's pre-trace function (which can add entry
        points). The matches are kept for post_trace_effects(), so the last
        call's are those for the code as finally traced."""
        memory_binary = session.current().memory.binary
        bytes_array = None
        for index, details in enumerate(session.current().snippets):
            if not getattr(details.pattern, "is_effect", False):
                continue
            if bytes_array is None:
                bytes_array = bytes([0 if x is None else x for x in memory_binary])
            matches = effectpattern.find_matches(self, details.pattern, bytes_array)
            self.effect_matches[index] = matches
            if details.pre_trace_function is None:
                continue
            for match in matches:
                key = (index, match.key())
                if key in self.effect_matches_seen:
                    continue
                self.effect_matches_seen.add(key)
                helper = EffectHelper(memory_binary, match, matches)
                if isinstance(details.pre_trace_function, str):
                    disassembly.comment_binary(helper.get_start_loc(), details.pre_trace_function, align=Align.INLINE, auto_generated=True)
                    continue
                try:
                    if details.pre_trace_parameter is None:
                        details.pre_trace_function(helper)
                    else:
                        details.pre_trace_function(helper, details.pre_trace_parameter)
                except SnippetRejected:
                    self.rejected_snippet_matches.add(key)

    def post_trace_effects(self):
        """Call the post-trace function of each effect pattern for each of
        its matches (see find_entry_points_from_effects())."""
        memory_binary = session.current().memory.binary
        for index, matches in sorted(self.effect_matches.items()):
            details = session.current().snippets[index]
            if details.post_trace_function is None:
                continue
            for match in matches:
                if (index, match.key()) in self.rejected_snippet_matches:
                    continue
                helper = EffectHelper(memory_binary, match, matches)
                if isinstance(details.post_trace_function, str):
                    disassembly.comment_binary(helper.get_start_loc(), details.post_trace_function, align=Align.INLINE, auto_generated=True)
                elif details.post_trace_parameter is None:
                    details.post_trace_function(helper)
                else:
                    details.post_trace_function(helper, details.post_trace_parameter)
