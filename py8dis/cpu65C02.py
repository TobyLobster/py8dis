"""
The 65C02 CPU

The 65C02 (the CMOS 6502, as in the BBC Master: load(..., "65C02")) is a
6502 with some new instructions and an addressing mode, and some cycle
counts changed. Cpu65C02 is a Cpu6502 with these added to (or changed in)
its opcode table:

- the new instructions: BRA, PHX, PHY, PLX, PLY, STZ, TSB, TRB, INC A, DEC
  A, BIT #imm, BIT zp,X, BIT addr,X and JMP (addr,X);
- the (zp) addressing mode, for ORA, AND, EOR, ADC, STA, LDA, CMP and SBC;
- the cycle counts that differ from the 6502's: the indexed shifts and
  rotates, JMP (addr), and ADC and SBC (an extra cycle in decimal mode).

The bit instructions of the Rockwell and WDC 65C02s (BBR, BBS, RMB and SMB)
and WDC's WAI and STP aren't included, and nor are the 65C02's unused
opcodes (see Cpu65C02.__init__()), so tracing stops at them.

Most of the new instructions use the 6502's opcode classes. BRA and JMP
(addr,X) have classes of their own (OpcodeUnconditionalBranch and
OpcodeJmpAbsX), and TSB, TRB and BIT #imm, which only change Z, have an
update function of their own (update_clear_z()). The
6502's analysis knows about the rest where it needs to (e.g. STZ in
Cpu6502._STORE_MNEMONICS). load() also turns on config.set_cmos(), for the
assemblers that need to be told (see commands._select_cpu()).
"""

from cpu6502 import *
from memorymanager import BinaryAddr, RuntimeAddr
import output
import session

class Cpu65C02(Cpu6502):
    """Class representing a 65C02 CPU (see the module's description)."""

    def __init__(self):
        """The 6502's opcode table, with the 65C02's changes."""
        super().__init__()

        # On a 65C02 undefined opcodes are guaranteed to be NOPs of
        # varying lengths. These are *not* implemented here, since most
        # code probably won't be executing them and it's probably
        # better to reduce the chances of arbitrary data being traced
        # as code.
        # (A user could perhaps opt in to them, as the 6502's undocumented
        # opcodes are the "6510" CPU: see cpu6510.py.)

        # Each opcode is categorised by how it affects A:
        #
        # (-) Does not touch A                  (e.g. CLC, PHP, LDX)
        # (U) Uses A, but doesn't change it     (e.g. CMP, STA, PHA)
        # (A) Adjusts A, via arithmetic/bitwise (e.g. ASL, ADC, AND)
        # (O) Overwrites A completely.          (e.g. LDA, PLA)
        #
        # and similarly for the X and Y registers.
        self.opcodes.update({
            # new instructions
            0x04: self.OpcodeZp(                    "TSB zp",       "U--", cycles="5",  update=self.update_clear_z),
            0x0c: self.OpcodeDataAbs(               "TSB addr",     "U--", cycles="6",  update=self.update_clear_z),
            0x12: self.OpcodeZp(                    "ORA (zp)",     "A--", cycles="5",  has_abs_version=False, update=self.update_clear_nza),
            0x14: self.OpcodeZp(                    "TRB zp",       "U--", cycles="5",  update=self.update_clear_z),
            0x1a: self.OpcodeImplied(               "INC A",        "A--", cycles="2",  update=self.make_increment('a')),
            0x1c: self.OpcodeDataAbs(               "TRB addr",     "U--", cycles="6",  update=self.update_clear_z),
            0x32: self.OpcodeZp(                    "AND (zp)",     "A--", cycles="5",  has_abs_version=False, update=self.update_clear_nza),
            0x34: self.OpcodeZp(                    "BIT zp,X",     "UU-", cycles="4",  update=self.update_bit),
            0x3c: self.OpcodeDataAbs(               "BIT addr,X",   "UU-", cycles="4",  update=self.update_bit),
            0x3a: self.OpcodeImplied(               "DEC A",        "A--", cycles="2",  update=self.make_decrement('a')),
            0x52: self.OpcodeZp(                    "EOR (zp)",     "A--", cycles="5",  has_abs_version=False, update=self.update_clear_nza),
            0x5a: self.OpcodeImplied(               "PHY",          "--U", cycles="3",  update=self.neutral),
            0x64: self.OpcodeZp(                    "STZ zp",       "---", cycles="3",  update=self.neutral),
            0x72: self.OpcodeZp(                    "ADC (zp)",     "A--", cycles="5e", has_abs_version=False, update=self.update_adc_sbc),
            0x74: self.OpcodeZp(                    "STZ zp,X",     "-U-", cycles="4",  update=self.neutral),
            0x7a: self.OpcodeImplied(               "PLY",          "--O", cycles="4",  update=self.update_clear_nz),
            0x7c: self.OpcodeJmpAbsX(               "JMP (addr,X)", "-U-", cycles="6"),
            0x80: self.OpcodeUnconditionalBranch(   "BRA offset",   "---", cycles="3d"),
            0x89: self.OpcodeImmediate(             "BIT #imm",     "U--", cycles="2",  update=self.update_clear_z), # BIT immediate only affects Z
            0x92: self.OpcodeZp(                    "STA (zp)",     "U--", cycles="5",  has_abs_version=False, update=self.neutral),
            0x9c: self.OpcodeDataAbs(               "STZ addr",     "---", cycles="4",  update=self.neutral),
            0x9e: self.OpcodeDataAbs(               "STZ addr,X",   "-U-", cycles="5",  update=self.neutral),
            0xb2: self.OpcodeZp(                    "LDA (zp)",     "O--", cycles="5",  has_abs_version=False, update=self.update_clear_nz),
            0xd2: self.OpcodeZp(                    "CMP (zp)",     "U--", cycles="5",  has_abs_version=False, update=self.update_compare),
            0xda: self.OpcodeImplied(               "PHX",          "-U-", cycles="3",  update=self.neutral),
            0xf2: self.OpcodeZp(                    "SBC (zp)",     "A--", cycles="5e", has_abs_version=False, update=self.update_adc_sbc),
            0xfa: self.OpcodeImplied(               "PLX",          "-O-", cycles="4",  update=self.update_clear_nz),

            # 6502 instructions with changed cycle counts
            0x1e: self.OpcodeDataAbs(               "ASL addr,X",   "-U-", cycles="6b", update=self.update_clear_nzc),
            0x3e: self.OpcodeDataAbs(               "ROL addr,X",   "-U-", cycles="6b", update=self.update_clear_nzc),
            0x5e: self.OpcodeDataAbs(               "LSR addr,X",   "-U-", cycles="6b", update=self.update_clear_nzc),
            0x6c: self.OpcodeJmpInd(                "JMP (addr)",   "---", cycles="6"),
            0x7e: self.OpcodeDataAbs(               "ROR addr,X",   "-U-", cycles="6b", update=self.update_clear_nzc),

            0x61: self.OpcodeZp(                    "ADC (zp,X)",   "AU-", cycles="6e", has_abs_version=False, update=self.update_adc_sbc),
            0x65: self.OpcodeZp(                    "ADC zp",       "A--", cycles="3e", update=self.update_adc_sbc),
            0x69: self.OpcodeImmediate(             "ADC #imm",     "A--", cycles="2e", update=self.update_adc_sbc),
            0x6d: self.OpcodeDataAbs(               "ADC addr",     "A--", cycles="4e", update=self.update_adc_sbc),
            0x71: self.OpcodeZp(                    "ADC (zp),Y",   "A-U", cycles="5c", has_abs_version=False, update=self.update_adc_sbc),
            0x75: self.OpcodeZp(                    "ADC zp,X",     "AU-", cycles="4e", update=self.update_adc_sbc),
            0x79: self.OpcodeDataAbs(               "ADC addr,Y",   "A-U", cycles="4c", has_zp_version=False, update=self.update_adc_sbc),
            0x7d: self.OpcodeDataAbs(               "ADC addr,X",   "AU-", cycles="4c", update=self.update_adc_sbc),
            0xe1: self.OpcodeZp(                    "SBC (zp,X)",   "AU-", cycles="6",  has_abs_version=False, update=self.update_adc_sbc),
            0xe5: self.OpcodeZp(                    "SBC zp",       "A--", cycles="3e", update=self.update_adc_sbc),
            0xe9: self.OpcodeImmediate(             "SBC #imm",     "A--", cycles="2",  update=self.update_adc_sbc),
            0xed: self.OpcodeDataAbs(               "SBC addr",     "A--", cycles="4",  update=self.update_adc_sbc),
            0xf1: self.OpcodeZp(                    "SBC (zp),Y",   "A-U", cycles="5c", has_abs_version=False, update=self.update_adc_sbc),
            0xf5: self.OpcodeZp(                    "SBC zp,X",     "AU-", cycles="4e", update=self.update_adc_sbc),
            0xf9: self.OpcodeDataAbs(               "SBC addr,Y",   "A-U", cycles="4c", has_zp_version=False, update=self.update_adc_sbc),
            0xfd: self.OpcodeDataAbs(               "SBC addr,X",   "AU-", cycles="4c", update=self.update_adc_sbc),
        })

    class OpcodeUnconditionalBranch(Cpu6502.Opcode):
        """BRA: a branch that's always taken, so only the target is traced,
        as for JMP. It has no update function, so nothing is known after
        it, and like JMP it ends a block (with a blank line after it, and
        the end of a straight run)."""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, cycles=cycles)

        def target(self, binary_addr):
            """The target's runtime address."""
            # (Like the 6502, wrapping round the top or bottom of memory)
            return RuntimeAddr(branch_target(binary_addr) & 0xffff)

        def abs_operand(self, binary_addr):
            """The target's runtime address."""
            return self.target(binary_addr)

        def update_references(self, binary_loc):
            """The target gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def could_be_call_to_subroutine(self):
            """True: the target could be a subroutine (a tail call)."""
            return True

        def is_block_end(self):
            """True: the code doesn't run on."""
            return True

        def is_unconditional_branch(self):
            """True: the code goes elsewhere."""
            return True

        def disassemble(self, binary_loc):
            """The target, in the branch's own move if it has one there (see
            Cpu.jump_target()), and no next instruction."""
            return [None] + session.current().cpu.jump_target(self.target(binary_loc.binary_addr), binary_loc, prefer_own_move=True)

        def instruction(self, binary_addr):
            """The instruction, with the target's label (see
            branch_operand())."""
            return branch_operand(self.mnemonic, binary_addr, self.target(binary_addr))


    class OpcodeJmpAbsX(Cpu6502.OpcodeAbs):
        """JMP (addr,X): a jump through a table of addresses at addr,
        indexed by X. As with JMP (addr), where it goes isn't known until
        the code runs, so tracing stops here; the table gets a label."""

        def __init__(self, instruction_template, reg_change, cycles="???"):
            super().__init__(instruction_template, reg_change, has_zp_version=False, cycles=cycles)

        def update_references(self, binary_loc):
            """The table gets a label (if it hasn't one), which this
            instruction refers to."""
            session.current().labels.labels[self.abs_operand(binary_loc.binary_addr)].add_reference(binary_loc)

        def is_block_end(self):
            """True: the code doesn't run on."""
            return True

        def disassemble(self, binary_loc):
            """Nothing more to trace from here."""
            return [None]

    def update_clear_z(self, binary_addr, state):
        """Z becomes unknown (TSB, TRB and BIT #imm, which only change Z)."""
        state.optimistic['z'] = None
        state.pessimistic['z'] = None

    def is_branch_to(self, binary_addr, target_runtime_addr):
        """As the 6502's (see Cpu6502.is_branch_to()), and BRA too."""
        c = classification.get_classification(binary_addr)

        # Special case for 65C02's unconditional branch instruction...
        if isinstance(c, Cpu65C02.OpcodeUnconditionalBranch):
            return c.target(binary_addr) == target_runtime_addr

        # ...otherwise everything is the same as 6502
        return Cpu6502.is_branch_to(self, binary_addr, target_runtime_addr)

    def pre_trace_with_regex(self):
        """As the 6502's (see Cpu6502.pre_trace_with_regex())."""
        super().pre_trace_with_regex()

    def post_trace_with_regex(self):
        """As the 6502's (see Cpu6502.post_trace_with_regex())."""
        super().post_trace_with_regex()
