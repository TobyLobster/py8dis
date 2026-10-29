import classification
import movemanager
import session
import trace
import utils
import labelmanager
from align import Align
import disassembly
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from memorymanager import BinaryLocation, BinaryAddr, RuntimeAddr

class SnippetRejected(Exception):
    """Raised by SnippetHelper.entry() when a match can't be code where it
    starts, because the bytes are already classified otherwise (see
    starts_mid_instruction()), or by SnippetHelper.reject() when a snippet's
    function finds the match isn't what it's looking for. The match is then
    ignored: the snippet's functions do nothing more with it, before or after
    tracing, and other snippets can match its bytes."""

def starts_mid_instruction(binary_addr):
    """Would an instruction at binary_addr overlap one already traced (or
    other classified data) without starting where it does? That is, is
    binary_addr inside another instruction or data, or does an instruction or
    data start in this instruction's operand?"""
    c = classification.get_classification(binary_addr)
    if c is not None:
        # Fine if an instruction already starts here (it's the same one)
        return not classification.is_code(binary_addr)
    opcode = session.current().cpu.opcodes.get(session.current().memory.binary[binary_addr])
    if opcode is None:
        return True
    return classification.is_classified(binary_addr + 1, opcode.length() - 1)

class SnippetDetails:
    def __init__(self, pre_trace_function, pre_trace_parameter, post_trace_function, post_trace_parameter, pattern):
        self.pre_trace_function = pre_trace_function
        self.pre_trace_parameter = pre_trace_parameter
        self.post_trace_function = post_trace_function
        self.post_trace_parameter = post_trace_parameter
        self.pattern = pattern

class SnippetHelper:
    def __init__(self, memory_binary, binary_loc, match, labels):
        self.memory_binary = memory_binary
        self.binary_loc    = binary_loc
        self.match         = match
        self.labels        = labels

    def get_start_loc(self):
        return self.binary_loc

    def get_binary_address_and_length(self, label_name, prioritise_definition=False):
        # Look for the 'declaration' of the label
        for priority in [prioritise_definition, not prioritise_definition]:
            for label in self.labels[label_name]:
                if label[1] == priority:
                    start, end = self.match.span(label[0])
                    if start is None or (start < 0):
                        # Match not found, could have been one of the '|' options that are not present... keep trying
                        continue
                    length = end - start
                    assert 0 <= start < 0x10000, "label='{0}' index={1} start={2}".format(label_name, label[0], start)
                    return (BinaryAddr(start), length)

        return (None, None)

    def get_binary_address(self, label_name, prioritise_definition=True):
        binary_addr, _ = self.get_binary_address_and_length(label_name, prioritise_definition=prioritise_definition)
        return binary_addr

    def get_binary_location(self, label_name, prioritise_definition=True):
        binary_addr, _ = self.get_binary_address_and_length(label_name, prioritise_definition=prioritise_definition)
        move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
        return BinaryLocation(binary_addr, move_id)

    def get_memory(self, label_name, offset=0):
        if isinstance(label_name, str):
            binary_addr, length = self.get_binary_address_and_length(label_name, prioritise_definition=False)
        else:
            binary_addr = label_name
            length = 1
        if binary_addr is not None:
            binary_addr += offset
            if length == 2:
                assert 0 <= binary_addr < 0xffff
                return self.memory_binary[binary_addr] + 256*self.memory_binary[binary_addr+1]
            elif length <= 1:
                assert 0 <= binary_addr < 0x10000
                return self.memory_binary[binary_addr]
            assert False, "length={0}, label={1}\nlabels:{2}".format(length, label_name, self.labels)
        return None

    def get_expr(self, label_name, *, label_offset=0, final_offset=0):
        binary_addr, length = self.get_binary_address_and_length(label_name, prioritise_definition=False)
        if binary_addr is not None:
            binary_addr += label_offset
            if length == 2:
                assert 0 <= binary_addr < 0xffff
                return classification.get_address16(binary_addr, offset=final_offset)
            elif length <= 1:
                assert 0 <= binary_addr < 0x10000
                return classification.get_address8(binary_addr, offset=0)
            assert False, "length={0}, label={1}\nlabels:{2}".format(length, label_name, self.labels)
        return None

    def get_state(self, label_name, offset=0):
        if isinstance(label_name, str):
            binary_addr, _ = self.get_binary_address_and_length(label_name, prioritise_definition=True)
        else:
            binary_addr = label_name
        if binary_addr is not None:
            binary_addr += offset
            assert 0 <= binary_addr < 0x10000
            return(session.current().cpu.cpu_states[binary_addr])

    def num_references(self, label_name):
        binary_loc = self.get_binary_location(label_name, prioritise_definition=True)

        assert session.current().trace.references is not None, "trying to get the number of references before we've calculated it"
        if binary_loc in session.current().trace.references:
            references = session.current().trace.references[binary_loc]
            return len(references)
        return 0

    def check_branch_matches(self, label_name):
        branch_operand_value = self.get_memory(label_name)
        branch_operand_addr = self.get_binary_address(label_name, prioritise_definition=False)
        definition_binary_addr = self.get_binary_address(label_name, prioritise_definition=True)

        # Check the branch operand will take us to the loop definition address
        expected_branch_operand = definition_binary_addr - branch_operand_addr-1
        if -128 <= expected_branch_operand <= 127:
            # bring into range 0-255
            expected_branch_operand = (256 + expected_branch_operand) & 255
            return expected_branch_operand == branch_operand_value
        return False

    def make_subtract_wrapped(self, source_label, snippet_label, offset):
        # To cope with an instruction like 'lda l0000-1,x' where the result operand wraps around
        # a 64k boundary e.g. equivalent to 'lda $ffff,x' we encode it as e.g. 'lda (l0000-1) & 0xffff,x'
        # to appease the assembler.
        label_runtime_addr = self.get_memory(snippet_label)

        assert label_runtime_addr is not None, f"Snippet label '{snippet_label}' not found"
    
        if (label_runtime_addr + offset) > 0xffff:
            return make_and(make_hex(0xffff), make_subtract(source_label, offset))
        return make_subtract(source_label, offset)

    def entry(self, runtime_addr = None):
        if runtime_addr is not None:
            assert not isinstance(runtime_addr, BinaryAddr)
            binary_addr, move_id = movemanager.r2b(RuntimeAddr(runtime_addr), None)
        else:
            binary_addr = self.get_start_loc().binary_addr
            runtime_addr = movemanager.b2r(binary_addr)
            move_id = self.get_start_loc().move_id
            # The match itself must be able to be code: not starting inside
            # an instruction already traced (snippets are matched after
            # tracing from the other entry points), or inside data
            if self.memory_binary[binary_addr] is not None and starts_mid_instruction(binary_addr):
                raise SnippetRejected()

        if self.memory_binary[binary_addr] is not None:
            # We add the entry point, but we don't call trace.cpu.add_entry() because this
            # also adds a label (even if without a name) which we don't want since this causes 
            # optimistic state tracking to restart at the label.
            session.current().cpu.entry_points.append(binary_addr)

    def reject(self):
        """Ignore this match (see SnippetRejected). Call it before making any
        changes for the match."""
        raise SnippetRejected()

    def blank_once(self, binary_loc):
        disassembly.annotate_binary(binary_loc, "", align=Align.BEFORE_LABEL, once_only=True)

    def has_explicit_label(self, binary_loc):
        binary_addr = self.get_start_loc().binary_addr
        runtime_addr = movemanager.b2r(binary_addr)
        move_id = self.get_start_loc().move_id

        if runtime_addr in session.current().labels.labels and session.current().labels.labels[runtime_addr].explicit_names:
            labels = session.current().labels.labels[runtime_addr].explicit_names[move_id]
            if labels:
                return True
            
        return False
    
    def __repr__(self):
        return "binary_addr = {0}, match={1}, labels={2}".format(self.binary_loc, self.match, self.labels)


def match_extent(match):
    """The (start, end) binary locations of an effect pattern's match (see
    EffectHelper.extent())."""
    addrs = []
    for i, item in match.satisfied.items():
        if match.pattern.lines[i].kind == 'memory':
            addrs.append(item.binary_addr)
            if item.value_operand is not None:
                addrs.append(item.value_operand - 1)
    if match.anchor is not None:
        addrs.append(match.anchor)
    start, last = min(addrs), max(addrs)
    end = last + classification.get_classification(last).length()
    moves = session.current().moves.move_id_for_binary_addr
    return (BinaryLocation(BinaryAddr(start), moves[start]), BinaryLocation(BinaryAddr(end), moves[end]))

class EffectHelper(SnippetHelper):
    """The SnippetHelper for a match of an effect pattern (see
    effectpattern.py). Its labels are those of the pattern's lines: an
    effect line's location is that of the store that satisfies it (none if
    it doesn't hold, e.g. an optional line), the anchor's is the anchor's.
    The start is the first of these locations, in address order."""

    def __init__(self, memory_binary, match, pattern_matches=()):
        self.effect_match = match
        # All the pattern's matches (e.g. for overlapping matches)
        self.pattern_matches = pattern_matches
        locations = match.locations()
        start = min(locations) if locations else None
        move_id = None if start is None else session.current().moves.move_id_for_binary_addr[start]
        super().__init__(memory_binary, BinaryLocation(start, move_id), None, None)

    def _line(self, label_name):
        pattern = self.effect_match.pattern
        if label_name in pattern.labels:
            return pattern.labels[label_name]
        if label_name == pattern.anchor_label and label_name is not None:
            return None
        raise KeyError("the effect pattern has no label '{0}'".format(label_name))

    def get_binary_address_and_length(self, label_name, prioritise_definition=False):
        i = self._line(label_name)
        if i is None:
            binary_addr = self.effect_match.anchor
        else:
            write = self.effect_match.satisfied.get(i)
            if write is None or self.effect_match.pattern.lines[i].kind != 'memory':
                return (None, None)
            binary_addr = write.binary_addr
        if binary_addr is None:
            return (None, None)
        return (BinaryAddr(binary_addr), classification.get_classification(binary_addr).length())

    def extent(self):
        """The (start, end) binary locations of the match's instructions
        and of the immediate loads of the values its stores store (e.g.
        from the 'lda #<handler' before 'sta vector' to after the last
        store), with end the location after the last one."""
        return match_extent(self.effect_match)

    def get_end_loc(self):
        """The location after the last of the match's instructions."""
        binary_addr = max(self.effect_match.locations())
        binary_addr += classification.get_classification(binary_addr).length()
        return BinaryLocation(BinaryAddr(binary_addr), session.current().moves.move_id_for_binary_addr[binary_addr])

    def matched(self, label_name):
        """Whether the named line holds (always True for one that isn't
        optional, and for the anchor)."""
        i = self._line(label_name)
        return i is None or i in self.effect_match.satisfied

    def value(self, name):
        """The value that a name in the pattern (e.g. 'nn1') matched, or
        None if the lines with it don't hold."""
        return self.effect_match.values.get(name)

    def binding(self, variable):
        """The address the variable was bound to (e.g. 'vec')."""
        return self.effect_match.binding[variable]

    def target(self, label_name):
        """The address of the named memory line, for this match."""
        i = self._line(label_name)
        return self.effect_match.pattern.targets[self.effect_match.binding_index][i]

    def store(self, label_name):
        """The cpu6502.MemoryWrite at the named memory line's address when
        the match was found, whether or not the line holds (e.g. a store of
        a value that isn't known), or None if there wasn't one."""
        return self.effect_match.writes.get(self._line(label_name))

    def __repr__(self):
        return "effect match at {0}: {1}".format(self.binary_loc, self.effect_match.key())


def vector_pattern(vector_addrs):
    """The effect pattern for code that sets one of the vectors (two byte
    addresses, low byte first) at vector_addrs to an address: the stores of
    the low byte ('lo', value 'lo_value') and the high byte ('hi',
    'hi_value'), in any order, with any registers. Both are optional, so a
    vector with only one byte set to a known value matches too."""
    return """
lo
?   [vector = {0}] = lo_value
hi
?   [vector+1] = hi_value
""".format(" | ".join("${0:04x}".format(addr) for addr in sorted(vector_addrs)))

def vector_handler(p, name_for_new_handler):
    """For a match of vector_pattern() with both bytes set, before tracing:
    the handler's address, which is labelled (with its first explicit name if
    it has one, otherwise name_for_new_handler(), called only then) and
    traced. Returns None for a half-set vector."""
    if not (p.matched('lo') and p.matched('hi')):
        return None
    handler = p.value('lo_value') + 256 * p.value('hi_value')
    if vector_handler_name(handler) is None:
        _, move_id = movemanager.r2b(RuntimeAddr(handler))
        disassembly.add_label(RuntimeAddr(handler), name_for_new_handler(), move_id, is_autogenerated=False)
    p.entry(handler)
    return handler

def vector_handler_name(handler):
    """The handler's first explicit name (as vector_handler() labels it), or
    None."""
    labels = session.current().labels.labels
    if handler in labels and labels[handler].explicit_names:
        for move_id, name_list in labels[handler].explicit_names.items():
            return name_list[0].text
    return None

def comment_vector(p, text):
    """For a match of vector_pattern(), after tracing, comment the code. If
    both bytes are set: before the first of its loads and stores, and the
    loads of the handler's address are written as the low and high bytes of
    its name (unless a load is already written otherwise, e.g. for two
    vectors set with the same high byte). The code is set off with a blank
    line before and after, around all the vector settings it overlaps, if
    any. If only one byte is set: inline, on the store."""
    if not (p.matched('lo') and p.matched('hi')):
        disassembly.comment_binary(p.get_binary_location('lo' if p.matched('lo') else 'hi'), text, align=Align.INLINE, auto_generated=True)
        return
    start, end = p.extent()
    disassembly.comment_binary(start, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

    # The vector settings that overlap this one (with both bytes set)
    first, last = start, end
    others = [match_extent(m) for m in p.pattern_matches if len(m.satisfied) == 2]
    changed = True
    while changed:
        changed = False
        for other_start, other_end in others:
            if other_start.binary_addr < last.binary_addr and first.binary_addr < other_end.binary_addr:
                if other_start.binary_addr < first.binary_addr:
                    first, changed = other_start, True
                if other_end.binary_addr > last.binary_addr:
                    last, changed = other_end, True
    labels = session.current().labels.labels
    runtime_addr = movemanager.b2r(first.binary_addr)
    if not (runtime_addr in labels and labels[runtime_addr].explicit_names.get(first.move_id)):
        p.blank_once(first)
    p.blank_once(last)

    name = vector_handler_name(p.value('lo_value') + 256 * p.value('hi_value'))
    for line, maker in (('lo', make_lo), ('hi', make_hi)):
        operand = p.store(line).value_operand
        if operand is not None:
            classification.add_expression(operand, maker(name), force=False)

def half_set_vector_text(p, description, hex2):
    """The comment for a half-set vector (see vector_pattern()), e.g. 'Set
    the low byte of the IRQ vector to $12', for the vector's description."""
    if p.matched('lo'):
        text = "Set the low byte of {0} to {1}".format(description, hex2(p.value('lo_value')))
        if p.store('hi') is not None:
            text += " (and the high byte to a value that isn't known)"
        return text
    text = "Set the high byte of {0} to {1}".format(description, hex2(p.value('hi_value')))
    if p.store('lo') is not None:
        text += " (and the low byte to a value that isn't known)"
    return text
