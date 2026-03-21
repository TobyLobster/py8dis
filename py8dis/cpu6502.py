import classification
import collections
import config
import disassembly
import labelmanager
import optionallabel
import mainformatter
import memorymanager
import movemanager
import re
import cpu
import trace
import utils
import snippets6502
import sys
from align import Align
from binaryaddrtype import BinaryAddrType
from memorymanager import RuntimeAddr, BinaryAddr, BinaryLocation
from snippets6502 import snippets
from snippethelper import *

memory_binary = memorymanager.memory_binary

OPCODE_JSR = 0x20
OPCODE_JMP = 0x4c
OPCODE_RTS = 0x60

class SubConst(object):
    """Data about a constant substitution.

    These are stored in substitute_constant_list"""

    def __init__(self, instruction, reg, constants_dict, define_constant):
        mnemonic, operand, operand_length, prefix, suffix, addr_modes = Cpu6502.parse_instruction(instruction)
        self.mnemonic       = mnemonic
        self.addr_modes     = addr_modes        # There can be two possible addressing modes, a zp and addr version
        self.operand        = operand           # This is a label
        self._opcode        = None              # not set yet
        self.reg            = reg
        self.constants_dict = constants_dict
        self.define_constant = define_constant

    def get_opcode(self, opcodes):
        # If already calculated, return it
        if self._opcode is not None:
            return self._opcode

        runtime_addr = self.get_operand_value()
        if len(self.addr_modes) > 1 and runtime_addr >= 0x100:
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
        # Look up label
        result = labelmanager.addr(self.operand)
        if result is not None:
            return result

        # TODO: Optimise!
        for addr in disassembly.optional_labels:
            if disassembly.optional_labels[addr].name == self.operand:
                return addr

        # Assume hex of some kind. Remove common prefixes.
        result = self.operand
        if result[0] in "&$":
            result = result[1:]
        return int(result, 16)


class RegState(object):
    def __init__(self):
        self.clear()

    def clear(self):
        self.value              = None      # Current value, if known
        self.previous_load_imm  = None      # The address of the previous load immediate instruction if no adjustments made since
        self.previous_load      = None      # The address of the previous load (immediate or otherwise) instruction if no adjustments made since
        self.previous_adjust    = None      # The address of the previous load or adjust instruction if present
        self.previous_use       = None      # The address of the previous 'read only use of a register' instruction if present

    def get_previous_load_imm_operand(self):
        if self.previous_load_imm is not None:
            return self.previous_load_imm+1
        return None

    def __repl__(self):
        return "value: {0}".format(self.value)

    def __str__(self):
        return self.__repl__()

class CpuStateDisposition(object):
    def __init__(self):
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

    def clear(self):
        self._d["a"].clear()
        self._d["x"].clear()
        self._d["y"].clear()
        self._d["n"] = None
        self._d["v"] = None
        self._d["d"] = None
        self._d["i"] = None
        self._d["z"] = None
        self._d["c"] = None

    def __getitem__(self, key):
        assert key in "axynvdizc"
        return self._d[key]

    def __setitem__(self, key, item):
        assert key in "axynvdizc"
        if key in "axy":
            if item is None:
                item = Cpu6502.RegState()
            assert isinstance(item, Cpu6502.RegState)
        else:
            assert item is None or utils.is_integer_type(item)
        self._d[key] = item

    def update_clear_nz(self, binary_addr):
        self._d['n'] = None
        self._d['z'] = None

    def update_clear_nza(self, binary_addr):
        self._d['n'] = None
        self._d['z'] = None
        self._d['a'].value = None

    def update_clear_nzc(self, binary_addr):
        assert binary_addr is not None
        self._d['n'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_clear_nzca(self, binary_addr):
        self._d['n'] = None
        self._d['z'] = None
        self._d['c'] = None
        self._d['a'].value = None

    def update_rora(self, binary_addr):
        if self._d['a'].value is not None and self._d['c'] is not None:
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
        assert binary_addr is not None
        self._d['n'] = None
        self._d['v'] = None
        self._d['z'] = None

    def update_adc_sbc(self, binary_addr):
        assert binary_addr is not None
        self._d['a'].value = None
        self._d['n'] = None
        self._d['v'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_all_flags(self, binary_addr):
        assert binary_addr is not None
        self._d['n'] = None
        self._d['v'] = None
        self._d['d'] = None
        self._d['i'] = None
        self._d['z'] = None
        self._d['c'] = None

    def update_AND_immediate(self, binary_addr):
        assert binary_addr is not None
        v = memory_binary[binary_addr+1]
        if self._d['a'].value is not None:
            # Value of A is known, so calculate new value of A
            v = self._d['a'].value & v
            self._d['a'].value = v

            # Update the flags based on new value of A
            self._d['n'] = ((v & 0x80) == 0x80)
            self._d['z'] = (v == 0)
        elif v < 0xff:
            if v == 0:
                # AND #0 sets the Z flag, and A=0
                self._d['z'] = 1
                self._d['a'].value = 0
            else:
                # AND with value $01-$fe leaves the Z flag unknown
                self._d['z'] = None

            # AND with value $00-$7f leaves the N flag clear
            if v < 0x80:
                self._d['n'] = 0

    def update_ORA_immediate(self, binary_addr):
        assert binary_addr is not None
        v = memory_binary[binary_addr+1]
        if self._d['a'].value is not None:
            # Value of A is known, so calculate new value of A
            v = self._d['a'].value | v
            self._d['a'].value = v

            # Update the flags based on new value of A
            self._d['n'] = ((v & 0x80) == 0x80)
            self._d['z'] = (v == 0)
        elif v > 0:
            # ORA with non-zero value means Z is clear
            self._d['z'] = 0
            if v >= 0x80:
                # ORA with a value $80-$ff, so set N flag
                self._d['n'] = 1

    def decrement(self, addr, reg):
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
        # Move to operand
        addr = BinaryAddr(addr)

        self[reg].value = v
        self['n'] = ((v & 0x80) == 0x80)
        self['z'] = (v == 0)
        self[reg].previous_load_imm = addr
        self[reg].previous_load     = addr
        self[reg].previous_adjust   = addr


    def transfer(self, addr, src_reg, dest_reg):
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
        if self[flag] is None:
            self[flag] = flag_state

    def show(self):
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
            return name.upper() if b else name.lower()
        s += " %s%s%s%s%s%s" % (flag('n'), flag('v'), flag('d'), flag('i'), flag('z'), flag('c'))
        return s

    def __repl__(self):
        return self.show()
    def __str__(self):
        return self.__repl__()

class Cpu6502(cpu.Cpu):
    """Singleton class representing a 6502 CPU"""

    # Addressing modes
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

    # Regex patterns that help identify the addressing modes
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

    class CpuState(object):
        def __init__(self):
            self.optimistic  = CpuStateDisposition()
            self.pessimistic = CpuStateDisposition()
            self.always_branch = False
            self.next_instruction = None

        def clear(self, *, pessimistic_only):
            self.pessimistic.clear()
            self.always_branch = False
            self.next_instruction = None
            if not pessimistic_only:
                self.optimistic.clear()

    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Cpu6502, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        super(Cpu6502, self).__init__()

        self.EMPTY_STATE = self.CpuState()

        self.code_analysis_fns.append(self.subroutine_argument_finder)  # TODO: For the subroutine() command? Is this used?
        self.code_analysis_fns.append(self.substitute_constants)        # If a subroutine is being called, we can infer context of initialising registers beforehand.
        self.code_analysis_fns.append(self.find_subroutine_calls)       # For the subroutine() command
        self.code_analysis_fns.append(self.show_register_knowledge)     # Show places where we use an inferred value of a register.

        # For labelling rts instructions numerically
        self.return_index = 0
        self.return_array = {}

        # indent_level_dict has binary addresses as the keys, and indent values as the values.

        # TODO: indent_level_dict is a bit of a hack (after all, arguably
        # byte/word directives etc should have it too) and should
        # probably be handled at a higher level by the code controlling
        # emission of text disassembly output
        self.indent_level_dict = collections.defaultdict(int)

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
            0x21: self.OpcodeZp(                "AND (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_clear_nzc),
            0x24: self.OpcodeZp(                "BIT zp",     "---", cycles="3",  update=self.update_bit),
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
            0xc0: self.OpcodeImmediate(         "CPY #imm",   "--U", cycles="2",  update=self.update_clear_nzc),
            0xc1: self.OpcodeZp(                "CMP (zp,X)", "UU-", cycles="6",  has_abs_version=False, update=self.update_clear_nzc),
            0xc4: self.OpcodeZp(                "CPY zp",     "--U", cycles="3",  update=self.update_clear_nzc),
            0xc5: self.OpcodeZp(                "CMP zp",     "U--", cycles="3",  update=self.update_clear_nzc),
            0xc6: self.OpcodeZp(                "DEC zp",     "---", cycles="5",  update=self.update_clear_nz),
            0xc8: self.OpcodeImplied(           "INY",        "--A", cycles="2",  update=self.make_increment('y')),
            0xc9: self.OpcodeImmediate(         "CMP #imm",   "U--", cycles="2",  update=self.update_clear_nzc),
            0xca: self.OpcodeImplied(           "DEX",        "-A-", cycles="2",  update=self.make_decrement('x')),
            0xcc: self.OpcodeDataAbs(           "CPY addr",   "--U", cycles="4",  update=self.update_clear_nzc),
            0xcd: self.OpcodeDataAbs(           "CMP addr",   "U--", cycles="4",  update=self.update_clear_nzc),
            0xce: self.OpcodeDataAbs(           "DEC addr",   "---", cycles="6",  update=self.update_clear_nz),
            0xd0: self.OpcodeConditionalBranch( "BNE offset", "---", cycles="2a", update=self.make_branch('z', True)),
            0xd1: self.OpcodeZp(                "CMP (zp),Y", "U-U", cycles="5b", has_abs_version=False, update=self.update_clear_nzc),
            0xd5: self.OpcodeZp(                "CMP zp,X",   "UU-", cycles="4",  update=self.update_clear_nzc),
            0xd6: self.OpcodeZp(                "DEC zp,X",   "-U-", cycles="6",  update=self.update_clear_nz),
            0xd8: self.OpcodeImplied(           "CLD",        "---", cycles="2",  update=self.make_update_flag('d', False)),
            0xd9: self.OpcodeDataAbs(           "CMP addr,Y", "--U", cycles="4f", has_zp_version=False, update=self.update_clear_nzc),
            0xdd: self.OpcodeDataAbs(           "CMP addr,X", "-U-", cycles="4f", update=self.update_clear_nzc),
            0xde: self.OpcodeDataAbs(           "DEC addr,X", "-U-", cycles="7",  update=self.update_clear_nz),
            0xe0: self.OpcodeImmediate(         "CPX #imm",   "-U-", cycles="2",  update=self.update_clear_nzc),
            0xe1: self.OpcodeZp(                "SBC (zp,X)", "AU-", cycles="6",  has_abs_version=False, update=self.update_adc_sbc),
            0xe4: self.OpcodeZp(                "CPX zp",     "-U-", cycles="3",  update=self.update_clear_nzc),
            0xe5: self.OpcodeZp(                "SBC zp",     "A--", cycles="3",  update=self.update_adc_sbc),
            0xe6: self.OpcodeZp(                "INC zp",     "---", cycles="5",  update=self.update_clear_nz),
            0xe8: self.OpcodeImplied(           "INX",        "-A-", cycles="2",  update=self.make_increment('x')),
            0xe9: self.OpcodeImmediate(         "SBC #imm",   "A--", cycles="2",  update=self.update_adc_sbc),
            0xea: self.OpcodeImplied(           "NOP",        "---", cycles="2",  update=self.neutral),
            0xec: self.OpcodeDataAbs(           "CPX addr",   "-U-", cycles="4",  update=self.update_clear_nzc),
            0xed: self.OpcodeDataAbs(           "SBC addr",   "A--", cycles="4",  update=self.update_adc_sbc),
            0xee: self.OpcodeDataAbs(           "INC addr",   "---", cycles="6",  update=self.update_clear_nz),
            0xf0: self.OpcodeConditionalBranch( "BEQ offset", "---", cycles="2a", update=self.make_branch('z', False)),
            0xf1: self.OpcodeZp(                "SBC (zp),Y", "A-U", cycles="5b", has_abs_version=False, update=self.update_adc_sbc),
            0xf5: self.OpcodeZp(                "SBC zp,X",   "AU-", cycles="4",  update=self.update_adc_sbc),
            0xf6: self.OpcodeZp(                "INC zp,X",   "---", cycles="6",  update=self.update_clear_nz),
            0xf8: self.OpcodeImplied(           "SED",        "---", cycles="2",  update=self.make_update_flag('d', True)),
            0xf9: self.OpcodeDataAbs(           "SBC addr,Y", "A-U", cycles="4f", has_zp_version=False, update=self.update_adc_sbc),
            0xfd: self.OpcodeDataAbs(           "SBC addr,X", "AU-", cycles="4f", update=self.update_adc_sbc),
            0xfe: self.OpcodeDataAbs(           "INC addr,X", "-U-", cycles="7",  update=self.update_clear_nz),
        }

    def get_target_binary_addr_preferring_given_move_id(self, runtime_addr, specific_move_id):
        # Try the specific move id first...
        binary_addr, _ = movemanager.r2b(runtime_addr, specific_move_id)
        if binary_addr is None:
            # If that doesn't work, try without a specific move id...
            binary_addr, _ = movemanager.r2b(runtime_addr)
            if binary_addr is None:
                assert False
                return []
        return [binary_addr]

    def parse_instruction(instruction):
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

    def hook_subroutine(self, runtime_addr, name, hook, warn=True):
        runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
        binary_loc = movemanager.r2b_checked(runtime_addr)
        memorymanager.check_data_loaded_at_binary_addr(binary_loc.binary_addr, 1, warn)
        self.add_entry(binary_loc.binary_addr, runtime_addr, binary_loc.move_id, name)
        self.subroutine_hooks[runtime_addr] = hook

    def default_subroutine_hook(self, runtime_addr, state, subroutine):
        _, move_id = movemanager.r2b(runtime_addr)
        runtime_loc = memorymanager.RuntimeLocation(runtime_addr, move_id)

        # Look for where we set up registers before the subroutine call
        for reg in ('a', 'x', 'y'):
            reg_addr = state.optimistic[reg].previous_adjust
            if reg_addr is not None:
                if reg in subroutine.on_entry:
                    disassembly.comment_binary(reg_addr, reg.upper() + "=" + subroutine.on_entry[reg], align=Align.INLINE, word_wrap=False, auto_generated=True)

        # Add subroutine title comment
        if subroutine.title and subroutine.runtime_addr != runtime_addr:
            disassembly.comment(runtime_addr, subroutine.title, align=Align.INLINE, word_wrap=False)

        # After the subroutine, check for results in registers being used
        if subroutine.on_exit:
            if subroutine.runtime_addr != runtime_addr:
                for reg in ('a', 'x', 'y'):
                    next_use = state.next_use[reg]
                    if next_use:
                        reg_runtime_addr = None if next_use is None else movemanager.b2r(next_use)
                        if reg_runtime_addr:
                            com = subroutine.on_exit[reg]
                            if com:
                                is_private_comment = com.startswith("()") and com.endswith(")")
                                if not is_private_comment:
                                    disassembly.comment(reg_runtime_addr, reg.upper() + "=" + subroutine.on_exit[reg], align=Align.INLINE)



    class Opcode(object):
        def __init__(self, instruction_template, reg_change, update=None, cycles="???"):

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
            return 1 + self.operand_length

        def is_code(self, binary_addr):
            return True

        def indent(self, binary_addr):
            trace.cpu.indent_level_dict[binary_addr] += 1

        def regular_update(self, binary_addr, state):
            """
            Update state based on reg_changes.

            Each opcode is categorised in reg_changes['a'] by how it affects A:

            (-) Does not touch A                   (e.g. CLC, PHP, LDX)
            (U) Uses A, but doesn't change it      (e.g. CMP, STA, PHA)
            (A) Adjusts A, via arithmetic/bitwise  (e.g. ASL, ADC, AND)
            (O) Overwrites A completely.           (e.g. LDA, PLA)
            (T) Overwrites A with another register (e.g. TXA, TYA)

            ...and similarly for the X and Y registers.
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
            # if there's a label at this address, then we lose all known (pessimistic) state.
            # This is because somewhere will be jumping to the label with unknown state.
            runtime_addr = movemanager.b2r(memorymanager.BinaryAddr(binary_addr))
            if runtime_addr is not None:
                if runtime_addr in labelmanager.labels:
                    state.clear(pessimistic_only=True)

        def update_cpu_state(self, binary_addr, state):
            # if there's a label at this address, then we lose all known pessimistic state.
            # This is because somewhere will be jumping to the label with unknown state.
            self.clear_pessimistic_state_if_label_here(binary_addr, state)

            # otherwise we update state if there's an update function
            if self.update is not None:
                self.regular_update(binary_addr, state)
                self.update(binary_addr, state)
            else:
                state.clear(pessimistic_only=False)

        def is_block_end(self):
            return False

        def target(self, binary_addr):
            return None

        def cycles_description(self, binary_addr):
            # Letter suffix on self.cycles explains cycle adjustments:
            #
            # a: +1 if branch occurs to same page, +2 if branch occurs to different page
            # b: +1 if page boundary crossed (zero page, post indirect addressing)
            # f: +1 if page boundary crossed (absolute address)

            # These three are 65c02 only:
            # c: +1 cycle if in decimal mode, +1 more cycle if indexing across a page boundary
            # d: +1 if branch target is to a different page
            # e: +1 cycle if in decimal mode

            letter = self.cycles[-1]
            if letter == "a":
                # A branch instruction
                result = int(self.cycles[:-1])

                # Check the target address to see if it is in the same page
                target = self.target(binary_addr)
                same_page = (target // 256) == (binary_addr // 256)

                if same_page:
                    return str(result) + "/" + str(result+1)
                return str(result) + "/" + str(result+2)

            if letter == "b":
                # zero page post indexed addressing
                result = int(self.cycles[:-1])
                return str(result) + "/" + str(result+1)

            if letter == "f":
                # absolute address indexed by X or Y
                # we only know the exact cycle count if it on a page boundary
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
                target = self.target(binary_addr)
                same_page = (target // 256) == (binary_addr // 256)

                if same_page:
                    return str(result)
                return str(result+1)

            if letter == "e":
                result = int(self.cycles[:-1])
                return str(result) + "/" + str(result+1)

            result = self.cycles
            return result

        def could_be_call_to_subroutine(self):
            return False

        def is_unconditional_branch(self):
            return False

        def as_string_list(self, binary_loc, annotations):
            lazy_string = utils.LazyString(utils.make_indent(trace.cpu.indent_level_dict.get(binary_loc.binary_addr, 0)) + "%s", self.as_string(binary_loc.binary_addr))
            result = [mainformatter.add_inline_comment_including_hexdump(binary_loc, self.length(), self.cycles_description(binary_loc.binary_addr), annotations, lazy_string)]
            if self.is_block_end() and config.get_blank_line_at_block_end():
                result.append("")
            return result

        def __repr__(self):
            return "{0}{1} {2}ADDR{3}".format(utils.make_indent(1),
                utils.force_case(self.mnemonic),
                self.prefix,
                utils.force_case(self.suffix))

        def __str__(self):
            return self.__repr__()

    class OpcodeReturn(Opcode):
        def __init__(self, instruction_template, reg_change, cycles="???"):
            super(Cpu6502.OpcodeReturn, self).__init__(instruction_template, reg_change, cycles=cycles)

        def update_references(self, binary_loc):
            pass

        def disassemble(self, binary_loc):
            return [None]

        def is_block_end(self):
            return True

        def as_string(self, binary_addr):
            return "%s%s" % (utils.make_indent(1), utils.force_case(self.mnemonic))


    class OpcodeImplied(Opcode):
        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super(Cpu6502.OpcodeImplied, self).__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            pass

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 1]

        def as_string(self, binary_addr):
            mnemonic = self.mnemonic
            if config.get_assembler().explicit_a and (self.addr_mode == Cpu6502.mode_accumulator):
                mnemonic += " A"
            return "%s%s" % (utils.make_indent(1), utils.force_case(mnemonic))


    class OpcodeImmediate(Opcode):
        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super(Cpu6502.OpcodeImmediate, self).__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            pass

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 2]

        def as_string(self, binary_addr):
            s = "%s%s #%s" % (utils.make_indent(1), utils.force_case(self.mnemonic), classification.get_constant8(binary_addr + 1))
            if (binary_addr + 1) not in classification.expressions and disassembly.format_hint.get(binary_addr + 1) is None:
                c = memory_binary[binary_addr + 1]
                if config.get_show_char_literals() and utils.isprint(c):
                    s += " %s '%s'" % (config.get_assembler().comment_prefix(), chr(c))
            return s


    class OpcodeZp(Opcode):
        def __init__(self, instruction_template, reg_change, has_abs_version=True, cycles="???", update=None):
            super(Cpu6502.OpcodeZp, self).__init__(instruction_template, reg_change, update=update, cycles=cycles)
            self._has_abs_version = has_abs_version

        def abs_operand(self, binary_addr):
            return memorymanager.RuntimeAddr(memory_binary[binary_addr + 1])

        def target(self, binary_addr):
            return memorymanager.RuntimeAddr(self.abs_operand(binary_addr))

        def update_references(self, binary_loc):
            trace.cpu.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 2]

        def as_string(self, binary_addr):
            address_string = classification.get_address8(binary_addr + 1)
            # TODO: We should avoid misassembly of a zp instruction by mistakenly
            # using a label with an absolute address. But we don't have the
            # technology to fix it automatically.
            # If the address string is a label name that has not yet been output,
            # then it's a forward reference, but we can't tell which label name
            # is to be used until the LazyStrings have been evaluated to the final
            # label name.
            return utils.LazyString("%s%s %s%s%s", utils.make_indent(1),
                utils.force_case(self.mnemonic),
                self.prefix,
                address_string,
                utils.force_case(self.suffix))


    class OpcodeAbs(Opcode):
        def __init__(self, instruction_template, reg_change, has_zp_version=True, cycles="???", update=None):
            super(Cpu6502.OpcodeAbs, self).__init__(instruction_template, reg_change, cycles=cycles, update=update)
            self._has_zp_version = has_zp_version

        def abs_operand(self, binary_addr):
            return memorymanager.RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def target(self, binary_addr):
            return memorymanager.RuntimeAddr(self.abs_operand(binary_addr))

        def has_zp_version(self):
            return self._has_zp_version

        def as_string(self, binary_addr):
            # We need to avoid misassembly of absolute instructions with zero-page
            # operands. (These are relatively rare in real code, but apart from the
            # fact we should still handle them even if they're rare, they can also
            # happen when the disassembly is imperfect and data is interpreted as
            # code. If we don't cope with them, bytes get lost and the disassembly
            # can't be correctly reassembled into a binary matching the input.)

            # ENHANCE: If we could evaluate expressions, *and*
            # (unlikely) we don't fail at disassembly time when we spot the
            # mismatch, we should force absolute addressing if the expression is a
            # zero page value and the value in the input is not.
            result1 = utils.force_case(self.mnemonic)
            result2 = utils.LazyString("%s%s%s", self.prefix, classification.get_address16(binary_addr + 1), utils.force_case(self.suffix))
            if not self.has_zp_version() or memorymanager.get_u16_binary(binary_addr + 1) >= 0x100:
                return utils.LazyString("%s%s %s", utils.make_indent(1), result1, result2)

            # This is an absolute instruction with a zero-page operand which could
            # be misassembled. If the assembler has a way to explicitly request
            # absolute addressing, we use that.
            force_abs_instruction = config.get_assembler().force_abs_instruction(result1, self.prefix, classification.get_address16(binary_addr + 1), utils.force_case(self.suffix))
            if force_abs_instruction is not None:
                return force_abs_instruction

            # This assembler has no way to force absolute addressing, so emit the
            # instruction as data with a comment showing what it is; the comment
            # includes an acme-style "+2" suffix to help indicate what's going on.
            operand = classification.get_address16(binary_addr + 1)
            return utils.LazyString("%s%s%s, <(%s), >(%s) ; %s+2 %s", utils.make_indent(1), config.get_assembler().byte_prefix(), classification.get_constant8(binary_addr), operand, operand, result1, result2)


    class OpcodeDataAbs(OpcodeAbs):
        def __init__(self, instruction_template, reg_change, has_zp_version=True, cycles="???", update=None):
            super(Cpu6502.OpcodeDataAbs, self).__init__(instruction_template, reg_change, has_zp_version, cycles=cycles, update=update)

        def update_references(self, binary_loc):
            ref = self.abs_operand(binary_loc.binary_addr)
            trace.cpu.labels[ref].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 3]


    class OpcodeJmpAbs(OpcodeAbs):
        def __init__(self, instruction_template, reg_change, cycles="???"):
            super(Cpu6502.OpcodeJmpAbs, self).__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def update_references(self, binary_loc):
            trace.cpu.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            return True

        def could_be_call_to_subroutine(self):
            return True

        def disassemble(self, binary_loc):
            # Get the destination location of the JMP
            target_runtime_addr = self.target(binary_loc.binary_addr)
            target_binary_addr, target_move_id = movemanager.r2b(target_runtime_addr)

            return [None, target_binary_addr]


    class OpcodeJmpInd(OpcodeAbs):
        def __init__(self, instruction_template, reg_change, cycles="???"):
            super(Cpu6502.OpcodeJmpInd, self).__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def abs_operand(self, binary_addr):
            return memorymanager.RuntimeAddr(memorymanager.get_u16_binary(binary_addr + 1))

        def update_references(self, binary_loc):
            trace.cpu.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            return True

        def is_unconditional_branch(self):
            return True

        def disassemble(self, binary_loc):
            return [None]


    class OpcodeJsr(OpcodeAbs):
        def __init__(self, instruction_template, reg_change, cycles="???"):
            super(Cpu6502.OpcodeJsr, self).__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def update_references(self, binary_loc):
            trace.cpu.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def could_be_call_to_subroutine(self):
            return True

        def is_unconditional_branch(self):
            return True

        def disassemble(self, binary_loc):
            assert isinstance(binary_loc.binary_addr, memorymanager.BinaryAddr)

            # Get the destination location of the JSR
            target_runtime_addr = self.target(binary_loc.binary_addr)
            target_binary_addr, target_move_id = movemanager.r2b(target_runtime_addr)

            # A hook only gets to return the "straight line" address to continue
            # tracing from (if there is one; it can return None if it wishes). Some
            # subroutines (e.g. jsr is_yx_zero:equw target_if_true, target_if_false)
            # might have no "straight line" case and want to return some labelled
            # entry points. This is supported by having the hook simply return None
            # and call entry() itself for the labelled entry points.

            def simple_subroutine_hook(target_runtime_addr, caller_runtime_addr):
                assert isinstance(target_runtime_addr, memorymanager.RuntimeAddr)
                assert isinstance(caller_runtime_addr, memorymanager.RuntimeAddr)

                return caller_runtime_addr + 3

            subroutine_hook = trace.cpu.subroutine_hooks.get(target_runtime_addr, simple_subroutine_hook)
            caller_runtime_addr = movemanager.b2r(binary_loc.binary_addr)

            with movemanager.move_id_for_binary_addr[binary_loc.binary_addr]:
                return_runtime_addr = subroutine_hook(target_runtime_addr, caller_runtime_addr)

            if return_runtime_addr is not None:
                return_runtime_addr = memorymanager.RuntimeAddr(return_runtime_addr)
                result = trace.cpu.get_target_binary_addr_preferring_given_move_id(return_runtime_addr, binary_loc.move_id)
                if len(result) == 0:
                    # The return runtime address could not be unambiguously converted into a binary
                    # address. It's highly likely the JSR is returning to the immediately following
                    # instruction, so if binary_addr+3 maps to the return runtime address, use that,
                    # otherwise give up and don't trace anything "after" the JSR.
                    simple_return_binary_addr = binary_loc.binary_addr + 3
                    if return_runtime_addr == movemanager.b2r(simple_return_binary_addr, binary_loc.move_id):
                        result = [simple_return_binary_addr]
                    else:
                        result = [None]
            else:
                result = [None]
            result += [target_binary_addr]
            return result


    class OpcodeConditionalBranch(Opcode):
        def __init__(self, instruction_template, reg_change, cycles="???", update=None):
            super(Cpu6502.OpcodeConditionalBranch, self).__init__(instruction_template, reg_change, cycles=cycles, update=update)

        def target(self, binary_addr):
            base = movemanager.b2r(binary_addr)
            return memorymanager.RuntimeAddr(base + 2 + utils.signed8(memorymanager.get_u8_binary(binary_addr + 1)))

        def abs_operand(self, binary_addr):
            return self.target(binary_addr)

        def update_references(self, binary_loc):
            trace.cpu.labels[self.target(binary_loc.binary_addr)].add_reference(binary_loc)

        def disassemble(self, binary_loc):
            return [binary_loc.binary_addr + 2] + trace.cpu.get_target_binary_addr_preferring_given_move_id(self.target(binary_loc.binary_addr), binary_loc.move_id)

        def could_be_call_to_subroutine(self):
            return True

        def update_cpu_state(self, binary_addr, state):
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
            else:
                # Assume conditional branch is not taken, we continue tracing
                if self.update is not None:
                    self.regular_update(binary_addr, state)
                    self.update(binary_addr, state)
                else:
                    state.clear(pessimistic_only=False)

        def as_string(self, binary_addr):
            label = disassembly.get_label(self.target(binary_addr), binary_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
            return utils.LazyString("%s%s %s", utils.make_indent(1), utils.force_case(self.mnemonic), label)


    def make_update_flag(self, flag, b):
        def update_flag(addr, state):
            state.optimistic[flag] = b
            state.pessimistic[flag] = b
        return update_flag

    def make_decrement(self, reg):
        def decrement(addr, state):
            state.pessimistic.decrement(addr, reg)
            state.optimistic.decrement(addr, reg)
        return decrement

    def make_increment(self, reg):
        def increment(addr, state):
            state.optimistic.increment(addr, reg)
            state.pessimistic.increment(addr, reg)
        return increment

    def make_load_immediate(self, reg):
        def load_immediate(addr, state):
            v = memory_binary[addr+1]
            state.optimistic.load_immediate(addr, reg, v)
            state.pessimistic.load_immediate(addr, reg, v)
        return load_immediate

    def make_transfer(self, src_reg, dest_reg):
        def transfer(addr, state):
            state.optimistic.transfer(addr, src_reg, dest_reg)
            state.pessimistic.transfer(addr, src_reg, dest_reg)
        return transfer

    def make_branch(self, flag, flag_state):
        # If a flag state is not currently known, this sets the flag state *assuming the branch is
        # NOT taken*. e.g. if "BNE addr" then we set the Z flag assuming the branch is not taken
        # i.e. Z=1
        # This let's us continue tracing with appropriate state from the next instruction after
        # the branch.

        # This also helps detect a pair of opposite conditional branches, marking 'ALWAYS branch':
        #    BNE addr1
        #    BEQ addr2              ; ALWAYS branch
        def update_branch(addr, state):
            state.optimistic.update_transfer(addr, flag, flag_state)
            state.pessimistic.update_transfer(addr, flag, flag_state)

        return update_branch

    def neutral(self, binary_addr, state):
        assert binary_addr is not None
        pass

    def update_clear_nz(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_clear_nz(binary_addr)
        state.pessimistic.update_clear_nz(binary_addr)

    def update_clear_nza(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_clear_nza(binary_addr)
        state.pessimistic.update_clear_nza(binary_addr)

    def update_clear_nzc(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_clear_nzc(binary_addr)
        state.pessimistic.update_clear_nzc(binary_addr)

    def update_clear_nzca(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_clear_nzca(binary_addr)
        state.pessimistic.update_clear_nzca(binary_addr)

    def update_rora(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_rora(binary_addr)
        state.pessimistic.update_rora(binary_addr)

    def update_bit(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_bit(binary_addr)
        state.pessimistic.update_bit(binary_addr)

    def update_adc_sbc(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_adc_sbc(binary_addr)
        state.pessimistic.update_adc_sbc(binary_addr)

    def update_all_flags(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_all_flags(binary_addr)
        state.pessimistic.update_all_flags(binary_addr)

    def update_AND_immediate(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_AND_immediate(binary_addr)
        state.pessimistic.update_AND_immediate(binary_addr)

    def update_ORA_immediate(self, binary_addr, state):
        assert binary_addr is not None
        state.optimistic.update_ORA_immediate(binary_addr)
        state.pessimistic.update_ORA_immediate(binary_addr)

    def is_subroutine_call(self, binary_addr):
        assert binary_addr is not None
        c = classification.get_classification(binary_addr)
        result = isinstance(c, trace.cpu.Opcode) and c.mnemonic == "JSR"
        return result

    def is_branch_to(self, binary_addr, target_runtime_addr):
        assert binary_addr is not None

        c = classification.get_classification(binary_addr)

        # TODO: hacky use of isinstance()
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
        if len(trace.subroutine_argument_finder_hooks) == 0:
            return

        binary_addr = 0
        state = None
        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)
            if c is not None:
                if state is None:
                    state = self.EMPTY_STATE

                if isinstance(c, trace.cpu.Opcode):
                    opcode = memory_binary[binary_addr]
                    if opcode in (OPCODE_JSR, OPCODE_JMP):
                        target = memorymanager.get_u16_binary(binary_addr + 1)
                        for hook in trace.subroutine_argument_finder_hooks:
                            if hook(memorymanager.RuntimeAddr(target),
                                state.optimistic['a'].get_previous_load_imm_operand(),
                                state.optimistic['x'].get_previous_load_imm_operand(),
                                state.optimistic['y'].get_previous_load_imm_operand()) is not None:
                                break
                state = trace.cpu.cpu_states[binary_addr]
                binary_addr += c.length()
            else:
                binary_addr += 1

    def scan_ahead_for_post_exit_state(self, binary_addr, state):
        assert binary_addr is not None
        scanning_for_register_usage = {'a': True, 'x': True, 'y': True }

        state.next_instruction = None
        state.next_use = {'a': None, 'x': None, 'y': None }

        newstate = trace.cpu.cpu_states[binary_addr]    # State after instruction following JSR

        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)

            # Must be classified
            if c is None:
                return

            # Stop at a nonentry point (i.e. not an instruction)
            if binary_addr not in self.traced_entry_points:
                return

            # Stop at the end of a code block
            if not c.is_code(binary_addr) or c.is_block_end():
                return

            # Must have known state
            if newstate is None:
                return

            # Must be an opcode
            if not isinstance(c, trace.cpu.Opcode):
                return

            if state.next_instruction is not None:
                # Beyond the first instruction as the call to the subroutine, a JSR/BRA is enough to end any register use knowledge
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
            newstate = trace.cpu.cpu_states[binary_addr]            # State after instruction at addr has executed

    def show_register_knowledge(self):
        """Adds comments to show any known state of the processor"""
        binary_addr = 0
        state = self.EMPTY_STATE

        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)
            if c is not None:
                state = trace.cpu.cpu_states[binary_addr]

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
                                move_id = movemanager.move_id_for_binary_addr[binary_addr]
                                binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                                formatter = config.get_assembler()
                                r = formatter.hex(r)
                                disassembly.comment_binary(binary_loc, "{0}={1}".format(reg.upper(), r), align=Align.INLINE, auto_generated=True)

                # Find "ALWAYS branch" instructions
                if isinstance(c, self.OpcodeConditionalBranch):
                    if state.always_branch:
                        move_id = movemanager.move_id_for_binary_addr[binary_addr]
                        binary_loc = movemanager.BinaryLocation(binary_addr, move_id)
                        disassembly.comment_binary(binary_loc, "ALWAYS branch", align=Align.INLINE, auto_generated=True)
                        disassembly.add_raw_annotation(binary_loc, "", align=Align.AFTER_LINE)  # add a blank line after ALWAYS branch
                binary_addr += c.length()
            else:
                binary_addr += 1
                state = self.EMPTY_STATE


    def find_subroutine_calls(self):
        """Finds calls to subroutines, and calls its hook function.

        Subroutines will have been registered previously with calls
        to the subroutine() command.

        The hook function receives the address, CPU state, and
        subroutine data and most likely uses it to label and/or comment
        the calling code.
        """

        binary_addr = 0
        state = None

        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)
            if c is not None:
                if state is None:
                    state = self.EMPTY_STATE

                if isinstance(c, trace.cpu.Opcode):
                    could_be_call_to_subroutine = c.could_be_call_to_subroutine()
                    binary_addr = memorymanager.BinaryAddr(binary_addr)
                    target = c.target(binary_addr)

                    # check each subroutine
                    for subroutine in trace.subroutines_list:
                        if not subroutine.hook_function:
                            continue

                        found = False
                        fall_through = False

                        # convert to binary address
                        sub_binary_addr, _ = movemanager.r2b(subroutine.runtime_addr)
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
                            if not fall_through and isinstance(c, trace.cpu.OpcodeJsr):
                                self.scan_ahead_for_post_exit_state(binary_addr, state)
                            subroutine.hook_function(runtime_addr, state, subroutine)

                state = trace.cpu.cpu_states[binary_addr]
                binary_addr += c.length()
            else:
                binary_addr += 1
                state = self.EMPTY_STATE

    def substitute_constants(self):
        if len(trace.substitute_constant_list) == 0:
            return

        binary_addr = 0
        state = None

        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)
            if c is None:
                binary_addr += 1
                continue

            if state is None:
                state = self.EMPTY_STATE

            if isinstance(c, trace.cpu.Opcode):
                opcode = memory_binary[binary_addr]

                # for each const_sub
                for const_sub in trace.substitute_constant_list:
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

            state = trace.cpu.cpu_states[binary_addr]
            binary_addr += c.length()

    def label_maker(self, lmd):
        # Label return1, return2 etc
        if config.get_label_return_instructions_numerically():
            # Only if the current label is autogenerated
            if lmd.is_autogenerated:
                defined_at_binary_addr, _ = movemanager.r2b(lmd.defined_as_runtime_addr, lmd.defined_in_move_id)
                c = classification.get_classification(defined_at_binary_addr)
                if c is not None:
                    if isinstance(c, trace.cpu.Opcode):
                        by = memorymanager.memory_binary[defined_at_binary_addr]
                        if by == OPCODE_RTS:
                            if not defined_at_binary_addr in self.return_array:
                                self.return_index += 1
                                self.return_array[defined_at_binary_addr] = self.return_index

                            lmd.name = "return_{0}".format(self.return_array[defined_at_binary_addr])

    # Regex searching (shared between 6502 and 65C02)
    def pre_trace_with_regex(self):
        # Make a byte array of memory
        memory_binary = memorymanager.memory_binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])

        # Remember which bytes are auto commented via a regex so we don't comment the same bytes again with a different regex.
        found_already = [False]*65536

        # for each snippet
        for details in snippets:
            if details.pre_trace_function is None:
                continue

            # Find all matches
            matches = re.finditer(details.pattern.whole_pattern, bytes_array)

            for match in matches:
                binary_addr = match.start()
                length = match.end() - match.start()
    
                # Check if any of the bytes are already commented on
                if any(found_already[binary_addr:binary_addr+length]):
                    continue

                move_id = movemanager.move_id_for_binary_addr[binary_addr]
                binary_loc = memorymanager.BinaryLocation(binary_addr, move_id)

                # Mark these bytes as True, already commented on
                found_already[binary_addr:binary_addr+length] = [True]*length
                helper = SnippetHelper(memory_binary, binary_loc, match, details.pattern.labels)
                if isinstance(details.pre_trace_function, str):
                    # A string means just add an inline string
                    disassembly.comment_binary(helper.get_start_loc(), details.pre_trace_function, align=Align.INLINE, auto_generated=True)
                else:
                    if details.pre_trace_parameter is None:
                        details.pre_trace_function(helper)
                    else:
                        details.pre_trace_function(helper, details.pre_trace_parameter)

    def post_trace_with_regex(self):
        # Make a byte array of memory
        memory_binary = memorymanager.memory_binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])

        # Remember which bytes are auto commented via a regex so we don't comment the same bytes again with a different regex.
        found_already = [False]*65536

        # for each snippet
        for details in snippets:
            if details.post_trace_function is None:
                continue

            # Find all matches
            matches = re.finditer(details.pattern.whole_pattern, bytes_array)

            for match in matches:
                binary_addr = match.start()
                length = match.end() - match.start()
    
                # Check if any of the bytes are already commented on
                if any(found_already[binary_addr:binary_addr+length]):
                    continue

                move_id = movemanager.move_id_for_binary_addr[binary_addr]
                binary_loc = memorymanager.BinaryLocation(binary_addr, move_id)

                # Mark these bytes as True, already commented on
                found_already[binary_addr:binary_addr+length] = [True]*length
                helper = SnippetHelper(memory_binary, binary_loc, match, details.pattern.labels)

                if isinstance(details.post_trace_function, str):
                    # A string means just add an inline string
                    disassembly.comment_binary(helper.get_start_loc(), details.post_trace_function, align=Align.INLINE, auto_generated=True)
                else:
                    if details.post_trace_parameter is None:
                        details.post_trace_function(helper)
                    else:
                        details.post_trace_function(helper, details.post_trace_parameter)
