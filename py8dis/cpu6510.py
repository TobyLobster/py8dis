"""
The 6510 (the Commodore 64's CPU): a 6502 with its undocumented opcodes.

Every NMOS 6502 runs its 105 undocumented opcodes the same way, so this CPU
suits any 6502 code that uses them (load(..., "6510")), e.g. C64 games and
demos, and some BBC Micro games. Plain "6502" doesn't trace them, since
treating unknown opcodes as code would turn data into nonsense instructions.

The names are those of "No More Secrets" (groepaz's "NMOS 6510 Unintended
Opcodes"), which ACME also uses: SLO, RLA, SRE, RRA, SAX, LAX, DCP, ISC,
ANC, ALR, ARR, SBX, SBC ($EB, the same as $E9), NOP (with operands), JAM,
and the unstable ANE, LXA, LAS, TAS, SHA, SHX and SHY.

They're written with their mnemonics for assemblers that accept them (see
Assembler.undocumented_6502_opcodes()), and otherwise as data bytes, with the
instruction in a comment.
"""

from cpu6502 import *
import expression
import output


class Cpu6510(Cpu6502):
    """A 6502 with its undocumented opcodes"""

    # (For assemblers that need to be told, e.g. acme's '!cpu 6510')
    has_undocumented_opcodes = True

    def __init__(self):
        super().__init__()

        # The register changes are described as for the 6502 (see Cpu6502):
        # (-) not touched, (U) used, (A) adjusted, (O) overwritten.
        self.opcodes.update({
            # SLO: shift memory left, then OR it into A
            0x03: self.OpcodeUndocumentedZp(     "SLO (zp,X)", "AU-", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x07: self.OpcodeUndocumentedZp(     "SLO zp",     "A--", cycles="5", update=self.update_clear_nzca),
            0x0f: self.OpcodeUndocumentedAbs(    "SLO addr",   "A--", cycles="6", update=self.update_clear_nzca),
            0x13: self.OpcodeUndocumentedZp(     "SLO (zp),Y", "A-U", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x17: self.OpcodeUndocumentedZp(     "SLO zp,X",   "AU-", cycles="6", update=self.update_clear_nzca),
            0x1b: self.OpcodeUndocumentedAbs(    "SLO addr,Y", "A-U", cycles="7", has_zp_version=False, update=self.update_clear_nzca),
            0x1f: self.OpcodeUndocumentedAbs(    "SLO addr,X", "AU-", cycles="7", update=self.update_clear_nzca),

            # RLA: rotate memory left, then AND it into A
            0x23: self.OpcodeUndocumentedZp(     "RLA (zp,X)", "AU-", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x27: self.OpcodeUndocumentedZp(     "RLA zp",     "A--", cycles="5", update=self.update_clear_nzca),
            0x2f: self.OpcodeUndocumentedAbs(    "RLA addr",   "A--", cycles="6", update=self.update_clear_nzca),
            0x33: self.OpcodeUndocumentedZp(     "RLA (zp),Y", "A-U", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x37: self.OpcodeUndocumentedZp(     "RLA zp,X",   "AU-", cycles="6", update=self.update_clear_nzca),
            0x3b: self.OpcodeUndocumentedAbs(    "RLA addr,Y", "A-U", cycles="7", has_zp_version=False, update=self.update_clear_nzca),
            0x3f: self.OpcodeUndocumentedAbs(    "RLA addr,X", "AU-", cycles="7", update=self.update_clear_nzca),

            # SRE: shift memory right, then EOR it into A
            0x43: self.OpcodeUndocumentedZp(     "SRE (zp,X)", "AU-", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x47: self.OpcodeUndocumentedZp(     "SRE zp",     "A--", cycles="5", update=self.update_clear_nzca),
            0x4f: self.OpcodeUndocumentedAbs(    "SRE addr",   "A--", cycles="6", update=self.update_clear_nzca),
            0x53: self.OpcodeUndocumentedZp(     "SRE (zp),Y", "A-U", cycles="8", has_abs_version=False, update=self.update_clear_nzca),
            0x57: self.OpcodeUndocumentedZp(     "SRE zp,X",   "AU-", cycles="6", update=self.update_clear_nzca),
            0x5b: self.OpcodeUndocumentedAbs(    "SRE addr,Y", "A-U", cycles="7", has_zp_version=False, update=self.update_clear_nzca),
            0x5f: self.OpcodeUndocumentedAbs(    "SRE addr,X", "AU-", cycles="7", update=self.update_clear_nzca),

            # RRA: rotate memory right, then add it to A (as ADC)
            0x63: self.OpcodeUndocumentedZp(     "RRA (zp,X)", "AU-", cycles="8", has_abs_version=False, update=self.update_adc_sbc),
            0x67: self.OpcodeUndocumentedZp(     "RRA zp",     "A--", cycles="5", update=self.update_adc_sbc),
            0x6f: self.OpcodeUndocumentedAbs(    "RRA addr",   "A--", cycles="6", update=self.update_adc_sbc),
            0x73: self.OpcodeUndocumentedZp(     "RRA (zp),Y", "A-U", cycles="8", has_abs_version=False, update=self.update_adc_sbc),
            0x77: self.OpcodeUndocumentedZp(     "RRA zp,X",   "AU-", cycles="6", update=self.update_adc_sbc),
            0x7b: self.OpcodeUndocumentedAbs(    "RRA addr,Y", "A-U", cycles="7", has_zp_version=False, update=self.update_adc_sbc),
            0x7f: self.OpcodeUndocumentedAbs(    "RRA addr,X", "AU-", cycles="7", update=self.update_adc_sbc),

            # SAX: store A AND X (no flags)
            0x83: self.OpcodeUndocumentedZp(     "SAX (zp,X)", "UU-", cycles="6", has_abs_version=False, update=self.neutral),
            0x87: self.OpcodeUndocumentedZp(     "SAX zp",     "UU-", cycles="3", update=self.neutral),
            0x8f: self.OpcodeUndocumentedAbs(    "SAX addr",   "UU-", cycles="4", update=self.neutral),
            0x97: self.OpcodeUndocumentedZp(     "SAX zp,Y",   "UUU", cycles="4", update=self.neutral),

            # LAX: load A and X
            0xa3: self.OpcodeUndocumentedZp(     "LAX (zp,X)", "OO-", cycles="6",  has_abs_version=False, update=self.update_clear_nz),
            0xa7: self.OpcodeUndocumentedZp(     "LAX zp",     "OO-", cycles="3",  update=self.update_clear_nz),
            0xaf: self.OpcodeUndocumentedAbs(    "LAX addr",   "OO-", cycles="4",  update=self.update_clear_nz),
            0xb3: self.OpcodeUndocumentedZp(     "LAX (zp),Y", "OOU", cycles="5b", has_abs_version=False, update=self.update_clear_nz),
            0xb7: self.OpcodeUndocumentedZp(     "LAX zp,Y",   "OOU", cycles="4",  update=self.update_clear_nz),
            0xbf: self.OpcodeUndocumentedAbs(    "LAX addr,Y", "OOU", cycles="4f", update=self.update_clear_nz),

            # DCP: decrement memory, then compare it with A (as CMP)
            0xc3: self.OpcodeUndocumentedZp(     "DCP (zp,X)", "UU-", cycles="8", has_abs_version=False, update=self.update_compare),
            0xc7: self.OpcodeUndocumentedZp(     "DCP zp",     "U--", cycles="5", update=self.update_compare),
            0xcf: self.OpcodeUndocumentedAbs(    "DCP addr",   "U--", cycles="6", update=self.update_compare),
            0xd3: self.OpcodeUndocumentedZp(     "DCP (zp),Y", "U-U", cycles="8", has_abs_version=False, update=self.update_compare),
            0xd7: self.OpcodeUndocumentedZp(     "DCP zp,X",   "UU-", cycles="6", update=self.update_compare),
            0xdb: self.OpcodeUndocumentedAbs(    "DCP addr,Y", "U-U", cycles="7", has_zp_version=False, update=self.update_compare),
            0xdf: self.OpcodeUndocumentedAbs(    "DCP addr,X", "UU-", cycles="7", update=self.update_compare),

            # ISC: increment memory, then subtract it from A (as SBC)
            0xe3: self.OpcodeUndocumentedZp(     "ISC (zp,X)", "AU-", cycles="8", has_abs_version=False, update=self.update_adc_sbc),
            0xe7: self.OpcodeUndocumentedZp(     "ISC zp",     "A--", cycles="5", update=self.update_adc_sbc),
            0xef: self.OpcodeUndocumentedAbs(    "ISC addr",   "A--", cycles="6", update=self.update_adc_sbc),
            0xf3: self.OpcodeUndocumentedZp(     "ISC (zp),Y", "A-U", cycles="8", has_abs_version=False, update=self.update_adc_sbc),
            0xf7: self.OpcodeUndocumentedZp(     "ISC zp,X",   "AU-", cycles="6", update=self.update_adc_sbc),
            0xfb: self.OpcodeUndocumentedAbs(    "ISC addr,Y", "A-U", cycles="7", has_zp_version=False, update=self.update_adc_sbc),
            0xff: self.OpcodeUndocumentedAbs(    "ISC addr,X", "AU-", cycles="7", update=self.update_adc_sbc),

            # Immediate
            0x0b: self.OpcodeUndocumentedImmediate("ANC #imm", "A--", cycles="2", update=self.update_ANC),
            0x2b: self.OpcodeUndocumentedImmediate("ANC #imm", "A--", cycles="2", update=self.update_ANC),
            0x4b: self.OpcodeUndocumentedImmediate("ALR #imm", "A--", cycles="2", update=self.update_ALR),
            0x6b: self.OpcodeUndocumentedImmediate("ARR #imm", "A--", cycles="2", update=self.update_adc_sbc),
            0xcb: self.OpcodeUndocumentedImmediate("SBX #imm", "UA-", cycles="2", update=self.update_SBX),
            0xeb: self.OpcodeUndocumentedImmediate("SBC #imm", "A--", cycles="2", update=self.update_adc_sbc),

            # NOPs, which read their operand (if any) and do nothing else
            0x1a: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0x3a: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0x5a: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0x7a: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0xda: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0xfa: self.OpcodeUndocumentedImplied(  "NOP",        "---", cycles="2",  update=self.neutral),
            0x80: self.OpcodeUndocumentedImmediate("NOP #imm",   "---", cycles="2",  update=self.neutral),
            0x82: self.OpcodeUndocumentedImmediate("NOP #imm",   "---", cycles="2",  update=self.neutral),
            0x89: self.OpcodeUndocumentedImmediate("NOP #imm",   "---", cycles="2",  update=self.neutral),
            0xc2: self.OpcodeUndocumentedImmediate("NOP #imm",   "---", cycles="2",  update=self.neutral),
            0xe2: self.OpcodeUndocumentedImmediate("NOP #imm",   "---", cycles="2",  update=self.neutral),
            0x04: self.OpcodeUndocumentedZp(       "NOP zp",     "---", cycles="3",  update=self.neutral),
            0x44: self.OpcodeUndocumentedZp(       "NOP zp",     "---", cycles="3",  update=self.neutral),
            0x64: self.OpcodeUndocumentedZp(       "NOP zp",     "---", cycles="3",  update=self.neutral),
            0x14: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0x34: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0x54: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0x74: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0xd4: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0xf4: self.OpcodeUndocumentedZp(       "NOP zp,X",   "-U-", cycles="4",  update=self.neutral),
            0x0c: self.OpcodeUndocumentedAbs(      "NOP addr",   "---", cycles="4",  update=self.neutral),
            0x1c: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),
            0x3c: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),
            0x5c: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),
            0x7c: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),
            0xdc: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),
            0xfc: self.OpcodeUndocumentedAbs(      "NOP addr,X", "-U-", cycles="4f", update=self.neutral),

            # JAM: the CPU stops (until reset), so tracing stops too
            **{opcode: self.OpcodeJam("JAM", "---") for opcode in (0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x92, 0xb2, 0xd2, 0xf2)},

            # The unstable ones: their results can depend on the CPU, its
            # temperature and so on, so what they change becomes unknown
            0x8b: self.OpcodeUndocumentedImmediate("ANE #imm",   "AU-", cycles="2",  update=self.update_clear_nza),
            0xab: self.OpcodeUndocumentedImmediate("LXA #imm",   "OO-", cycles="2",  update=self.update_clear_nz),
            0xbb: self.OpcodeUndocumentedAbs(      "LAS addr,Y", "OOU", cycles="4f", has_zp_version=False, update=self.update_clear_nz),
            0x9b: self.OpcodeUndocumentedAbs(      "TAS addr,Y", "UUU", cycles="5",  has_zp_version=False, update=self.neutral),
            0x93: self.OpcodeUndocumentedZp(       "SHA (zp),Y", "UUU", cycles="6",  has_abs_version=False, update=self.neutral),
            0x9f: self.OpcodeUndocumentedAbs(      "SHA addr,Y", "UUU", cycles="5",  has_zp_version=False, update=self.neutral),
            0x9e: self.OpcodeUndocumentedAbs(      "SHX addr,Y", "-UU", cycles="5",  has_zp_version=False, update=self.neutral),
            0x9c: self.OpcodeUndocumentedAbs(      "SHY addr,X", "-UU", cycles="5",  has_zp_version=False, update=self.neutral),
        })
        assert len(self.opcodes) == 256

    class Undocumented:
        """An undocumented opcode: written as an instruction for assemblers
        that accept it (Assembler.undocumented_6502_opcodes()), otherwise as
        data bytes (the opcode, then the operand), with the instruction in a
        comment."""

        undocumented = True

        def instruction(self, binary_addr):
            instruction = super().instruction(binary_addr)
            memory_binary = session.current().memory.binary
            opcode = memory_binary[binary_addr]
            assembler = config.get_assembler()
            if opcode in assembler.undocumented_6502_opcodes():
                # (The assembler's own name for it, e.g. acme's ASR for ALR)
                instruction.mnemonic = assembler.undocumented_6502_mnemonic(instruction.mnemonic)
            else:
                instruction.form = output.Instruction.UNDOCUMENTED
                instruction.data_byte = expression.Num(opcode, "hex2")
                instruction.operand_length = self.operand_length
            return instruction

    class OpcodeUndocumentedImplied(Undocumented, Cpu6502.OpcodeImplied):
        pass

    class OpcodeUndocumentedImmediate(Undocumented, Cpu6502.OpcodeImmediate):
        pass

    class OpcodeUndocumentedZp(Undocumented, Cpu6502.OpcodeZp):
        pass

    class OpcodeUndocumentedAbs(Undocumented, Cpu6502.OpcodeDataAbs):
        pass

    class OpcodeJam(Undocumented, Cpu6502.OpcodeReturn):
        """JAM (also called KIL or HLT): the CPU stops until it's reset, so
        nothing follows it."""

        def __init__(self, instruction_template, reg_change):
            super().__init__(instruction_template, reg_change, cycles="halts")

    def update_ANC(self, binary_addr, state):
        """ANC #imm: A = A AND imm, with C set to N (as if shifted out)"""
        for s in (state.optimistic, state.pessimistic):
            s.update_AND_immediate(binary_addr)
            s['c'] = s['n']

    def update_ALR(self, binary_addr, state):
        """ALR #imm: A = (A AND imm) LSR 1"""
        memory_binary = session.current().memory.binary
        imm = memory_binary[binary_addr + 1]
        for s in (state.optimistic, state.pessimistic):
            a = s['a'].value
            if a is not None:
                v = a & imm
                s['c'] = v & 1
                v >>= 1
                s['a'].value = v
                s['z'] = (v == 0)
            else:
                # The bit shifted out into C is clear if imm's bit 0 is
                s['c'] = 0 if (imm & 1) == 0 else None
                s['z'] = True if imm in (0, 1) else None
                if imm in (0, 1):
                    s['a'].value = 0
            # (A shift right always clears N)
            s['n'] = 0

    def update_SBX(self, binary_addr, state):
        """SBX #imm: X = (A AND X) - imm, setting N, Z and C as a compare
        does (ignoring the carry in and the D flag)"""
        memory_binary = session.current().memory.binary
        imm = memory_binary[binary_addr + 1]
        for s in (state.optimistic, state.pessimistic):
            a, x = s['a'].value, s['x'].value
            if a is not None and x is not None:
                t = a & x
                v = (t - imm) & 0xff
                s['x'].value = v
                s['c'] = (t >= imm)
                s['n'] = (v & 0x80) == 0x80
                s['z'] = (v == 0)
            else:
                s['x'].value = None
                s['n'] = None
                s['z'] = None
                s['c'] = True if imm == 0 else None


# The undocumented opcodes that acme (with '!cpu 6510') and 64tass (with
# '.cpu "6502i"') assemble from their mnemonics: where an instruction has
# several opcodes (e.g. ANC is &0b and &2b; JAM and the NOPs have many), each
# uses only one, so the others are written as data. (Found by assembling each
# with acme 0.97 of 31 Jan 2021 and 64tass 1.59.3120, which give the same 70.)
ASSEMBLED_UNDOCUMENTED_OPCODES = frozenset([
    0x02, 0x03, 0x04, 0x07, 0x0b, 0x0c, 0x0f, 0x13, 0x14, 0x17, 0x1b, 0x1c, 0x1f, 0x23,
    0x27, 0x2f, 0x33, 0x37, 0x3b, 0x3f, 0x43, 0x47, 0x4b, 0x4f, 0x53, 0x57, 0x5b, 0x5f,
    0x63, 0x67, 0x6b, 0x6f, 0x73, 0x77, 0x7b, 0x7f, 0x80, 0x83, 0x87, 0x8b, 0x8f, 0x93,
    0x97, 0x9b, 0x9c, 0x9e, 0x9f, 0xa3, 0xa7, 0xab, 0xaf, 0xb3, 0xb7, 0xbb, 0xbf, 0xc3,
    0xc7, 0xcb, 0xcf, 0xd3, 0xd7, 0xdb, 0xdf, 0xe3, 0xe7, 0xef, 0xf3, 0xf7, 0xfb, 0xff,
])
