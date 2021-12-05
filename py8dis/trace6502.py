import collections # TODO!?
import six # TODO!?

import config
import classification
import config
import disassembly
import labelmanager
import movemanager
import trace
import utils

memory_binary = config.memory_binary
labels = labelmanager.labels
jsr_hooks = {}
subroutine_argument_finder_hooks = [] # TODO: move?

# TODO: Perhaps rename this function to make its behaviour more obvious, once I understand it myself...
# TODO: This returns a list so it can return an empty list when it wants to say "give up" and this "just works" when appending the result to other lists
def apply_move(runtime_addr):
    # TODO: This is a re-implementation using movemanager, may want to get rid of apply_move() fn later
    binary_addr, _ = movemanager.r2b(runtime_addr)
    if binary_addr is None:
        return []
    return [binary_addr]

# TODO: Perhaps rename this function to make its behaviour more obvious, once I understand it myself...
def apply_move2(target, context):
    # TODO: Rewritten in terms of movemanager - change this eventually? I think the rewrite does the same thing, but it may not, or it may do but not be right anyway...
    with movemanager.moved(movemanager.move_id_for_binary_addr[context]):
        #if context in (0x8fda, 0x2fda):
        #    print("XAL", hex(target), movemanager.r2b(target))
        return apply_move(target)

# TODO: Get rid of this function? It has one caller and doesn't seem to add much value.
def add_jsr_hook(addr, hook):
    # TODO: This almost certainly wants to be doing an r2b(addr)
    assert addr not in jsr_hooks
    jsr_hooks[addr] = hook

# TODO: This is a user command, it should possibly take an optional move_id or respect the "current move ID"
# TODO: Need to clarify runtime/binary here
def hook_subroutine(runtime_addr, name, hook, warn=True):
    runtime_addr = utils.RuntimeAddr(runtime_addr)
    binary_addr, move_id = movemanager.r2b_checked(runtime_addr)
    # TODO: Should probably warn rather than assert in other fns too
    if warn:
        utils.check_data_loaded_at_binary_addr(binary_addr)
    trace.add_entry(binary_addr, name, move_id)
    add_jsr_hook(runtime_addr, hook)

def signed8(i):
    assert 0 <= i <= 255
    if i >= 0x80:
        return i - 256
    else:
        return i

def get_u8(i):
    assert memory_binary[i] is not None
    return memory_binary[i]


# TODO: Not a high priority, but once we have support for generating arbitrary inline
# comments, we could potentially track things like inx/dex/iny/dey which adjust a
# constant slightly and when we infer what that constant means (e.g. a keycode) we could
# add an inline comment so we end up with something like "dex ; X=keycode_p" - at the
# moment we can only do this for raw constants which we can convert into an expression.
class CpuState(object):
    def __init__(self):
        self.clear()

    def clear(self):
        self._d = {
            # For A/X/Y, value is (integer value if known, address of integer
            # value if set by LDA/X/Y #).
            "a": [None, None],
            "x": [None, None],
            "y": [None, None],
            # For flags, value is True/False if known.
            "n": None,
            "v": None,
            "d": None,
            "i": None,
            "z": None,
            "c": None,
        }

    def __getitem__(self, key):
        assert key in "axynvdizc"
        return self._d[key]

    def __setitem__(self, key, item):
        assert key in "axynvdizc"
        if key in "axy":
            if item is None:
                item = [None, None]
            assert len(item) == 2
            assert item[1] is None or item[0] is not None
        else:
            assert item is None or isinstance(item, six.integer_types)
        self._d[key] = item


class Opcode(object):
    # TODO: indent_level is a bit of a hack (after all, arguably byte/word directives etc should have it too) and should probably be handled at a higher level by the code controlling emission of text disassembly output
    indent_level = collections.defaultdict(int)

    def __init__(self, mnemonic, operand_length, suffix=None, update=None):
        self.mnemonic = mnemonic
        self.suffix = suffix if suffix is not None else ""
        self.prefix = "(" if ")" in self.suffix else ""
        self.update = update
        self.operand_length = operand_length
        self.indent_level = 0

    def is_mergeable(self):
        return False

    def length(self):
        return 1 + self.operand_length

    def is_code(self, addr):
        return True

    def indent(self, addr):
        Opcode.indent_level[addr] += 1

    def update_cpu_state(self, addr, state):
        if self.update is not None:
            self.update(addr, state)
        else:
            state.clear()

    def is_block_end(self):
        # TODO: This should perhaps be defined on individual instructions or opcode classes.
        return self.mnemonic in ("JMP", "RTS", "BRA")

    def as_string_list(self, addr):
        result = [utils.add_hex_dump(utils.LazyString("    "*Opcode.indent_level.get(addr, 0) + "%s", self.as_string(addr)), addr, self.length())]
        if self.is_block_end() and config.blank_line_at_block_end:
            result.append("")
        return result


class OpcodeImplied(Opcode):
    def __init__(self, mnemonic, update=None):
        super(OpcodeImplied, self).__init__(mnemonic, 0, update=update)
        self.mnemonic = mnemonic
        self.operand_length = 0

    def update_references(self, addr):
        pass

    def disassemble(self, addr):
        return [addr + 1]

    def as_string(self, addr):
        mnemonic = self.mnemonic
        if (not config.formatter().explicit_a) and mnemonic.endswith(" A"):
            mnemonic = mnemonic[:-2]
        return "    %s" % utils.force_case(mnemonic)


class OpcodeImmediate(Opcode):
    def __init__(self, mnemonic, update=None):
        super(OpcodeImmediate, self).__init__(mnemonic, 1, update=update)

    def update_references(self, addr):
        pass

    def disassemble(self, addr):
        return [addr + 2]

    def as_string(self, addr):
        s = "    %s #%s" % (utils.force_case(self.mnemonic), classification.get_constant8(addr + 1))
        if (addr + 1) not in classification.expressions and disassembly.format_hint.get(addr + 1) is None:
            c = memory_binary[addr + 1]
            if config.show_char_literals and utils.isprint(c):
                s += " %s '%s'" % (config.formatter().comment_prefix(), chr(c))
        return s


class OpcodeZp(Opcode):
    def __init__(self, mnemonic, suffix=None, update=None):
        super(OpcodeZp, self).__init__(mnemonic, 1, suffix, update=update)

    def abs_operand(self, addr):
        return memory_binary[addr + 1]

    def update_references(self, addr):
        labels[self.abs_operand(addr)].add_reference(addr)

    def disassemble(self, addr):
        return [addr + 2]

    def as_string(self, addr):
        return utils.LazyString("    %s %s%s%s", utils.force_case(self.mnemonic), self.prefix, classification.get_address8(addr + 1), utils.force_case(self.suffix))


class OpcodeAbs(Opcode):
    def __init__(self, mnemonic, suffix=None, has_zp_version=True, update=None):
        super(OpcodeAbs, self).__init__(mnemonic, 2, suffix, update=update)
        self._has_zp_version = has_zp_version

    def abs_operand(self, addr):
        return utils.get_u16(addr + 1)

    def has_zp_version(self):
        return self._has_zp_version

    def as_string(self, addr):
        # We need to avoid misassembly of absolute instructions with zero-page
        # operands. These are relatively rare in real code, but apart from the
        # fact we should still handle them even if they're rare, they can also
        # happen when the disassembly is imperfect and data is interpreted as
        # code. If we don't cope with them, bytes get lost and the disassembly
        # can't be correctly reassembled into a binary matching the input.
        # TODO: If we could evaluate expressions, *and* (unlikely) we don't
        # fail at disassembly time when we spot the mismatch, we should force
        # absolute addressing if the expression is a zero page value and the
        # value in the input is not.
        result1 = utils.force_case(self.mnemonic)
        result2 = utils.LazyString("%s%s%s", self.prefix, classification.get_address16(addr + 1), utils.force_case(self.suffix))
        if not self.has_zp_version() or utils.get_u16(addr + 1) >= 0x100:
            return utils.LazyString("    %s %s", result1, result2)

        # This is an absolute instruction with a zero-page operand which could
        # be misassembled. If the assembler has a way to explicitly request
        # absolute addressing, we use that.
        force_abs_instruction = config.formatter().force_abs_instruction(result1, self.prefix, classification.get_address16(addr + 1), utils.force_case(self.suffix))
        if force_abs_instruction is not None:
            return force_abs_instruction

        # This assembler has no way to force absolute addressing, so emit the
        # instruction as data with a comment showing what it is; the comment
        # includes an acme-style "+2" suffix to help indicate what's going on.
        operand = classification.get_address16(addr + 1)
        return utils.LazyString("%s%s, <(%s), >(%s) ; %s+2 %s", config.formatter().byte_prefix(), classification.get_constant8(addr), operand, operand, result1, result2)


class OpcodeDataAbs(OpcodeAbs):
    def __init__(self, mnemonic, suffix=None, has_zp_version=True, update=None):
        super(OpcodeDataAbs, self).__init__(mnemonic, suffix, has_zp_version, update=update)

    def update_references(self, addr):
        labels[self.abs_operand(addr)].add_reference(addr)

    def disassemble(self, addr):
        #assert addr != 0x8ae3
        return [addr + 3]


class OpcodeJmpAbs(OpcodeAbs):
    def __init__(self):
        super(OpcodeJmpAbs, self).__init__("JMP", has_zp_version=False)

    def _target(self, addr):
        return utils.RuntimeAddr(utils.get_u16(addr + 1))

    def abs_operand(self, addr):
        return self._target(addr)

    # TODO: Might want to rename this function to reflect the fact it creates labels as well/instead as updating trace.references
    def update_references(self, addr):
        labels[self._target(addr)].add_reference(addr)
        #trace.references[self._target(addr)].add(addr)

    def disassemble(self, addr):
        #print("PCC %s" % apply_move(self._target(addr)))
        # TODO: Should the apply_move() call be inside _target and/or abs_operand? Still feeling my way here...
        return [None] + apply_move2(self._target(addr), addr)
        return [None] + apply_move(self._target(addr))


class OpcodeJmpInd(OpcodeAbs):
    def __init__(self):
        super(OpcodeJmpInd, self).__init__("JMP", ")", has_zp_version=False)

    def update_references(self, addr):
        labels[utils.get_u16(addr + 1)].add_reference(addr)

    def disassemble(self, addr):
        return [None]


class OpcodeJsr(OpcodeAbs):
    def __init__(self):
        super(OpcodeJsr, self).__init__("JSR", has_zp_version=False)

    def _target(self, addr):
        return utils.RuntimeAddr(utils.get_u16(addr + 1))

    def abs_operand(self, addr):
        return self._target(addr)

    def update_references(self, addr):
        labels[self._target(addr)].add_reference(addr)
        #trace.references[self._target(addr)].add(addr)

    def disassemble(self, binary_addr):
        assert isinstance(binary_addr, utils.BinaryAddr)
        # A hook only gets to return the "straight line" address to continue
        # tracing from (if there is one; it can return None if it wishes). Some
        # subroutines (e.g. jsr is_yx_zero:equw target_if_true, target_if_false)
        # might have no "straight line" case and want to return some labelled
        # entry points. This is supported by having the hook simply return None
        # and call entry() itself for the labelled entry points.
        # TODO: Do we need to apply_move() here or in _target() or in abs_operand() or before/after jsr_hooks.get()?
        target_runtime_addr = self._target(binary_addr)
        def simple_jsr_hook(target_runtime_addr, caller_runtime_addr):
            assert isinstance(target_runtime_addr, utils.RuntimeAddr)
            assert isinstance(caller_runtime_addr, utils.RuntimeAddr)
            # TODO: It might be possible the following assertion fails if the moves
            # in effect are sufficiently tricky, but I'll leave it for now as it
            # may catch bugs - once the code is more trusted it can be removed
            # if it's technically incorrect.
            assert movemanager.r2b_checked(caller_runtime_addr)[0] == binary_addr
            return caller_runtime_addr + 3
        jsr_hook = jsr_hooks.get(target_runtime_addr, simple_jsr_hook)
        caller_runtime_addr = movemanager.b2r(binary_addr)
        with movemanager.moved(movemanager.move_id_for_binary_addr[binary_addr]):
            return_runtime_addr = jsr_hook(target_runtime_addr, caller_runtime_addr)
        if return_runtime_addr is not None:
            return_runtime_addr = utils.RuntimeAddr(return_runtime_addr)
            result = apply_move(return_runtime_addr)
            if len(result) == 0:
                # The return runtime address could not be unambiguously converted into a binary
                # address. It's highly likely the JSR is returning to the immediately following
                # instruction, so if binary_addr+3 maps to the return runtime address, use that,
                # otherwise give up and don't trace anything "after" the JSR.
                simple_return_binary_addr = binary_addr + 3
                if return_runtime_addr == movemanager.b2r(simple_return_binary_addr):
                    result = [simple_return_binary_addr]
                else:
                    result = [None]
        else:
            result = [None]
        result += apply_move(target_runtime_addr)
        return result


class OpcodeReturn(Opcode):
    def __init__(self, mnemonic):
        super(OpcodeReturn, self).__init__(mnemonic, 0)

    def update_references(self, addr):
        pass

    def disassemble(self, addr):
        return [None]

    def as_string(self, addr):
        return "    %s" % utils.force_case(self.mnemonic)


class OpcodeConditionalBranch(Opcode):
    def __init__(self, mnemonic):
        super(OpcodeConditionalBranch, self).__init__(mnemonic, 1)

    def _target(self, addr):
        base = movemanager.b2r(addr)
        return base + 2 + signed8(get_u8(addr + 1))

    def abs_operand(self, addr):
        return self._target(addr)

    def update_references(self, addr):
        labels[self._target(addr)].add_reference(addr)
        #trace.references[self._target(addr)].add(addr)

    def disassemble(self, addr):
        # TODO: As elsewhere where exactly do we need to apply_move()? Perhaps we don't need it  here given it's relative, feeling my way..
        return [addr + 2] + apply_move2(self._target(addr), addr)

    def update_cpu_state(self, addr, state):
        # TODO: I think this is "right" - in our optimistic model (at least), a
        # branch invalidates everything. Consider "ldy #3:.label:dey:bne label" -
        # in the optimistic model we ignore labels and the only way we don't
        # finish that sequence assuming y=2 is if the branch invalidates.
        state.clear()

    def as_string(self, addr):
        return utils.LazyString("    %s %s", utils.force_case(self.mnemonic), disassembly.get_label(self._target(addr), addr))


def show_cpu_state(state):
    s = ""
    def reg(r):
        v = state[r][0]
        if v is None:
            return "--"
        return utils.plainhex2(v)
    s += "A:%s X:%s Y:%s" % (reg('a'), reg('x'), reg('y'))
    def flag(name):
        b = state[name]
        if b is None:
            return "-"
        return name.upper() if b else name.lower()
    s += " %s%s%s%s%s%s" % (flag('n'), flag('v'), flag('d'), flag('i'), flag('z'), flag('c'))
    return s


def make_corrupt_rnz(reg):
    def corrupt(addr, state):
        state[reg] = None
        state['n'] = None
        state['z'] = None
    return corrupt

def make_corrupt_rnzc(reg):
    def corrupt(addr, state):
        state[reg] = None
        state['n'] = None
        state['z'] = None
        state['c'] = None
    return corrupt

def make_update_flag(flag, b):
    def update_flag(addr, state):
        state[flag] = b
    return update_flag

# TODO: make_decrement() and make_increment() are probably not that useful -
# it's all very well knowing the value of a register, but without an address to
# use with expr() it doesn't help that much. If they *are* useful, we should
# probably make adc # and sbc # update the value where possible.

def make_decrement(reg):
    def decrement(addr, state):
        v = state[reg][0]
        if v is not None:
            v -= 1
            if v == -1:
                v = 0xff
            state[reg] = (v, None)
    return decrement

def make_increment(reg):
    def increment(addr, state):
        v = state[reg][0]
        if v is not None:
            v += 1
            if v == 0x100:
                v = 0
            state[reg] = (v, None)
    return increment

def make_load_immediate(reg):
    def load_immediate(addr, state):
        v = memory_binary[addr+1]
        state[reg] = (v, addr+1)
        state['n'] = ((v & 0x80) == 0x80)
        state['z'] = (v == 0)
    return load_immediate

def make_transfer(src_reg, dest_reg):
    def transfer(addr, state):
        state[dest_reg] = state[src_reg]
        v = state[dest_reg][0]
        if v is not None:
            state['n'] = ((v & 0x80) == 0x80)
            state['z'] = (v == 0)
    return transfer

def neutral(addr, state):
    pass

def update_anz(addr, state):
    return make_corrupt_rnz('a')(addr, state)

def update_anzc(addr, state):
    return make_corrupt_rnzc('a')(addr, state)

def update_xnz(addr, state):
    return make_corrupt_rnz('x')(addr, state)

def update_ynz(addr, state):
    return make_corrupt_rnz('y')(addr, state)

def update_nz(addr, state):
    state['n'] = None
    state['z'] = None

def update_nzc(addr, state):
    state['n'] = None
    state['z'] = None
    state['c'] = None

def update_bit(addr, state):
    state['n'] = None
    state['v'] = None
    state['z'] = None

def update_adc_sbc(addr, state):
    state['n'] = None
    state['v'] = None
    state['z'] = None
    state['c'] = None

def corrupt_flags(addr, state):
    state['n'] = None
    state['v'] = None
    state['d'] = None
    state['i'] = None
    state['z'] = None
    state['c'] = None


# ENHANCE: Some of these opcodes might benefit from has_zp_version=False; I
# haven't done an exhaustive search to determine if there are any others not yet
# marked.
opcodes = {
    0x00: OpcodeReturn("BRK"),
    0x01: OpcodeZp("ORA", ",X)", update=update_anz),
    0x05: OpcodeZp("ORA", update=update_anz),
    0x06: OpcodeZp("ASL", update=update_nzc),
    0x08: OpcodeImplied("PHP", update=neutral),
    0x09: OpcodeImmediate("ORA", update=update_anz),
    0x0a: OpcodeImplied("ASL A", update=update_anzc),
    0x0d: OpcodeDataAbs("ORA", update=update_anz),
    0x0e: OpcodeDataAbs("ASL", update=update_nzc),
    0x10: OpcodeConditionalBranch("BPL"),
    0x11: OpcodeZp("ORA", "),Y", update=update_anz),
    0x15: OpcodeZp("ORA", ",X", update=update_anz),
    0x16: OpcodeZp("ASL", ",X", update=update_nzc),
    0x18: OpcodeImplied("CLC", update=make_update_flag('c', False)),
    0x19: OpcodeDataAbs("ORA", ",Y", has_zp_version=False, update=update_anz),
    0x1d: OpcodeDataAbs("ORA", ",X", update=update_anz),
    0x1e: OpcodeDataAbs("ASL", ",X", update=update_nzc),
    0x20: OpcodeJsr(),
    0x21: OpcodeZp("AND", ",X)", update=update_anzc),
    0x24: OpcodeZp("BIT", update=update_bit),
    0x25: OpcodeZp("AND", update=update_anz),
    0x26: OpcodeZp("ROL", update=update_nzc),
    0x28: OpcodeImplied("PLP", update=corrupt_flags),
    0x29: OpcodeImmediate("AND", update=update_anz),
    0x2a: OpcodeImplied("ROL A", update=update_anzc),
    0x2c: OpcodeDataAbs("BIT", update=update_bit),
    0x2d: OpcodeDataAbs("AND", update=update_anz),
    0x2e: OpcodeDataAbs("ROL", update=update_nzc),
    0x30: OpcodeConditionalBranch("BMI"),
    0x31: OpcodeZp("AND", "),Y", update=update_anz),
    0x35: OpcodeZp("AND", ",X", update=update_anz),
    0x36: OpcodeZp("ROL", ",X", update=update_nzc),
    0x38: OpcodeImplied("SEC", update=make_update_flag('c', True)),
    0x39: OpcodeDataAbs("AND", ",Y", has_zp_version=False, update=update_anz),
    0x3d: OpcodeDataAbs("AND", ",X", update=update_anz),
    0x3e: OpcodeDataAbs("ROL", ",X", update=update_nzc),
    0x40: OpcodeReturn("RTI"),
    0x41: OpcodeZp("EOR", ",X)", update=update_anz),
    0x45: OpcodeZp("EOR", update=update_anz),
    0x46: OpcodeZp("LSR", update=update_nzc),
    0x48: OpcodeImplied("PHA", update=neutral),
    0x49: OpcodeImmediate("EOR", update=update_anz),
    0x4a: OpcodeImplied("LSR A", update=update_anzc),
    0x4c: OpcodeJmpAbs(),
    0x4d: OpcodeDataAbs("EOR", update=update_anz),
    0x4e: OpcodeDataAbs("LSR", update=update_nzc),
    0x50: OpcodeConditionalBranch("BVC"),
    0x51: OpcodeZp("EOR", "),Y", update=update_anz),
    0x55: OpcodeZp("EOR", ",X", update=update_anz),
    0x56: OpcodeZp("LSR", ",X",  update=update_nzc),
    0x58: OpcodeImplied("CLI", update=make_update_flag('i', False)),
    0x59: OpcodeDataAbs("EOR", ",Y", has_zp_version=False, update=update_anz),
    0x5d: OpcodeDataAbs("EOR", ",X", update=update_anz),
    0x5e: OpcodeDataAbs("LSR", ",X", update=update_nzc),
    0x60: OpcodeReturn("RTS"),
    0x61: OpcodeZp("ADC", ",X)", update=update_adc_sbc),
    0x65: OpcodeZp("ADC", update=update_adc_sbc),
    0x66: OpcodeZp("ROR", update=update_nzc),
    0x68: OpcodeImplied("PLA", update=update_anz),
    0x69: OpcodeImmediate("ADC", update=update_adc_sbc),
    0x6a: OpcodeImplied("ROR A", update=update_anzc),
    0x6c: OpcodeJmpInd(),
    0x6d: OpcodeDataAbs("ADC", update=update_adc_sbc),
    0x6e: OpcodeDataAbs("ROR", update=update_nzc),
    0x70: OpcodeConditionalBranch("BVS"),
    0x71: OpcodeZp("ADC", "),Y", update=update_adc_sbc),
    0x75: OpcodeZp("ADC", ",X", update=update_adc_sbc),
    0x76: OpcodeZp("ROR", ",X", update=update_nzc),
    0x78: OpcodeImplied("SEI", update=make_update_flag('i', True)),
    0x79: OpcodeDataAbs("ADC", ",Y", has_zp_version=False, update=update_adc_sbc),
    0x7d: OpcodeDataAbs("ADC", ",X", update=update_adc_sbc),
    0x7e: OpcodeDataAbs("ROR", ",X", update=update_nzc),
    0x81: OpcodeZp("STA", ",X)", update=neutral),
    0x84: OpcodeZp("STY", update=neutral),
    0x85: OpcodeZp("STA", update=neutral),
    0x86: OpcodeZp("STX", update=neutral),
    0x88: OpcodeImplied("DEY", update=make_decrement('y')),
    0x8a: OpcodeImplied("TXA", update=make_transfer('x', 'a')),
    0x8c: OpcodeDataAbs("STY", update=neutral),
    0x8d: OpcodeDataAbs("STA", update=neutral),
    0x8e: OpcodeDataAbs("STX", update=neutral),
    0x90: OpcodeConditionalBranch("BCC"),
    0x91: OpcodeZp("STA", "),Y", update=neutral),
    0x94: OpcodeZp("STY", ",X", update=neutral),
    0x95: OpcodeZp("STA", ",X", update=neutral),
    0x96: OpcodeZp("STX", ",Y", update=neutral),
    0x98: OpcodeImplied("TYA", update=make_transfer('y', 'a')),
    0x99: OpcodeDataAbs("STA", ",Y", has_zp_version=False, update=neutral),
    0x9a: OpcodeImplied("TXS", update=neutral), # we don't model S at all
    0x9d: OpcodeDataAbs("STA", ",X", update=neutral),
    0xa0: OpcodeImmediate("LDY", update=make_load_immediate('y')),
    0xa1: OpcodeZp("LDA", ",X)", update=update_anz),
    0xa2: OpcodeImmediate("LDX", update=make_load_immediate('x')),
    0xa4: OpcodeZp("LDY", update=update_ynz),
    0xa5: OpcodeZp("LDA", update=update_anz),
    0xa6: OpcodeZp("LDX", update=update_xnz),
    0xa8: OpcodeImplied("TAY", update=make_transfer('a', 'y')),
    0xa9: OpcodeImmediate("LDA", update=make_load_immediate('a')),
    0xaa: OpcodeImplied("TAX", update=make_transfer('a', 'x')),
    0xac: OpcodeDataAbs("LDY", update=update_ynz),
    0xad: OpcodeDataAbs("LDA", update=update_anz),
    0xae: OpcodeDataAbs("LDX", update=update_xnz),
    0xb0: OpcodeConditionalBranch("BCS"),
    0xb1: OpcodeZp("LDA", "),Y", update=update_anz),
    0xb4: OpcodeZp("LDY", ",X", update=update_anz),
    0xb5: OpcodeZp("LDA", ",X", update=update_anz),
    0xb8: OpcodeImplied("CLV", update=make_update_flag('v', False)),
    0xb9: OpcodeDataAbs("LDA", ",Y", has_zp_version=False, update=update_anz),
    0xba: OpcodeImplied("TSX", update=update_xnz),
    0xbc: OpcodeDataAbs("LDY", ",X", update=update_ynz),
    0xbd: OpcodeDataAbs("LDA", ",X", update=update_anz),
    0xbe: OpcodeDataAbs("LDX", ",Y", update=update_xnz),
    0xc0: OpcodeImmediate("CPY", update=update_nzc),
    0xc1: OpcodeZp("CMP", ",X)", update=update_nzc),
    0xc4: OpcodeZp("CPY", update=update_nzc),
    0xc5: OpcodeZp("CMP", update=update_nzc),
    0xc6: OpcodeZp("DEC", update=update_nz),
    0xc8: OpcodeImplied("INY", update=make_increment('y')),
    0xc9: OpcodeImmediate("CMP", update=update_nzc),
    0xca: OpcodeImplied("DEX", update=make_decrement('x')),
    0xcc: OpcodeDataAbs("CPY", update=update_nzc),
    0xcd: OpcodeDataAbs("CMP", update=update_nzc),
    0xce: OpcodeDataAbs("DEC", update=update_nz),
    0xd0: OpcodeConditionalBranch("BNE"),
    0xd1: OpcodeZp("CMP", "),Y", update=update_nzc),
    0xd5: OpcodeZp("CMP", ",X", update=update_nzc),
    0xd6: OpcodeZp("DEC", ",X", update=update_nz),
    0xd8: OpcodeImplied("CLD", update=make_update_flag('d', False)),
    0xd9: OpcodeDataAbs("CMP", ",Y", has_zp_version=False, update=update_nzc),
    0xdd: OpcodeDataAbs("CMP", ",X", update=update_nzc),
    0xde: OpcodeDataAbs("DEC", ",X", update=update_nz),
    0xe0: OpcodeImmediate("CPX", update=update_nzc),
    0xe1: OpcodeZp("SBC", ",X)", update=update_adc_sbc),
    0xe4: OpcodeZp("CPX", update=update_nzc),
    0xe5: OpcodeZp("SBC", update=update_adc_sbc),
    0xe6: OpcodeZp("INC", update=update_nz),
    0xe8: OpcodeImplied("INX", update=make_increment('x')),
    0xe9: OpcodeImmediate("SBC", update=update_adc_sbc),
    0xea: OpcodeImplied("NOP", update=neutral),
    0xec: OpcodeDataAbs("CPX", update=update_nzc),
    0xed: OpcodeDataAbs("SBC", update=update_adc_sbc),
    0xee: OpcodeDataAbs("INC", update=update_nz),
    0xf0: OpcodeConditionalBranch("BEQ"),
    0xf1: OpcodeZp("SBC", "),Y", update=update_adc_sbc),
    0xf5: OpcodeZp("SBC", ",X", update=update_adc_sbc),
    0xf6: OpcodeZp("INC", ",X", update=update_nz),
    0xf8: OpcodeImplied("SED", update=make_update_flag('d', True)),
    0xf9: OpcodeDataAbs("SBC", ",Y", has_zp_version=False, update=update_adc_sbc),
    0xfd: OpcodeDataAbs("SBC", ",X", update=update_adc_sbc),
    0xfe: OpcodeDataAbs("INC", ",X", update=update_nz),
}


def disassemble_instruction(binary_addr):
    assert isinstance(binary_addr, utils.BinaryAddr)
    opcode_value = memory_binary[binary_addr]
    if opcode_value not in opcodes:
        return [None]
    opcode = opcodes[opcode_value]
    # If we hit something that's already classified, we can't/don't re-classify
    # it but that doesn't mean we can't continue to trace until something breaks
    # the control flow.
    if disassembly.is_classified(binary_addr, 1 + opcode.operand_length):
        # TODO: The machinations required to format the comment here are a bit
        # annoying.
        s = opcode.as_string(binary_addr)
        def late_formatter():
            return utils.add_hex_dump(config.formatter().comment_prefix() + " overlapping: " + str(s)[4:], binary_addr, opcode.length())
        disassembly.add_raw_annotation(binary_addr, utils.LazyString("%s", late_formatter))
    else:
        disassembly.add_classification(binary_addr, opcode)
        opcode.update_references(binary_addr)
    return opcode.disassemble(binary_addr)

# TODO?
# TODO: Should this maybe accept JMP abs too, since that could just be a tail call?
# Or perhaps we should insist (in the caller of is_subroutine_call()) that there is
# at least one JSR to count as a subroutine, but if there is at least one JSR we also
# allow any unconditional branch to it without disqualifying it?
def is_subroutine_call(addr):
    c = disassembly.classifications[addr]
    return isinstance(c, Opcode) and c.mnemonic == "JSR"

def is_branch_to(addr, target):
    c = disassembly.classifications[addr]
    import trace65c02 # TODO!
    # TODO: hacky use of isinstance()
    if isinstance(c, OpcodeConditionalBranch) or isinstance(c, trace65c02.OpcodeUnconditionalBranch):
        return c._target(addr) == target
    if isinstance(c, OpcodeJmpAbs):
        return utils.get_u16(addr + 1) == target
    return False

# TODO: Move? We do need to do this before setting trace_done though (I think)...
# Note that this does *not* check for labels breaking up a sequence. We're not
# optimising code here, we are making an inference from a series of straight
# line instructions - the fact that the sequence might *also* be entered
# part-way through via a label doesn't invalidate that inference.
def subroutine_argument_finder():
    if len(subroutine_argument_finder_hooks) == 0:
        return

    addr = 0
    state = CpuState()
    while addr < 0x10000:
        c = disassembly.classifications[addr]
        if c is not None:
            # TODO: Hacky use of isinstance()
            if isinstance(c, Opcode):
                opcode = config.memory_binary[addr]
                opcode_jsr = 0x20
                opcode_jmp = 0x4c
                if opcode in (opcode_jsr, opcode_jmp):
                    target = utils.get_u16(addr + 1)
                    for hook in subroutine_argument_finder_hooks:
                        def get(reg):
                            return state[reg][1]
                        if hook(target, get('a'), get('x'), get('y')) is not None:
                            break
            state = disassembly.cpu_state_optimistic[addr]
            addr += c.length()
        else:
            addr += 1

config.set_disassemble_instruction(disassemble_instruction)
trace.code_analysis_fns.append(subroutine_argument_finder) # TODO!?

# TODO: do commmands entry() and no_entry() need to do an lookup of move()s? The user will probably be addressing routines at their relocated destination addresses, but the tracing process works with source addresses. (We might want some facility for a user to specify source addresses to these functions or variants, as this provides ultimate disambiguation in terms of forcing/preventing tracing of particular bits of code.)
