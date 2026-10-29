"""Effect patterns: snippets that match what code does, rather than the bytes
of its instructions.

A regex snippet (snippet6502.py) matches a sequence of instructions, so it
depends on their order and on the registers used: 'lda #<h : sta vec : lda
#>h : sta vec+1' and 'ldy #>h : sty vec+1 : ldx #<h : stx vec' set the same
vector, but need different patterns. An effect pattern describes the effect
instead, e.g.:

    lo_store
    ?   [vec = $0200 | $0202 | $0204] = nn1
    hi_store
    ?   [vec+1] = nn2

and is matched using the CPU state (Cpu6502.memory_writes()), so it matches
however the code does it. It's registered with register_snippet() etc. like
a regex snippet; a snippet is an effect pattern if any of its lines is one
of these:

- '[target] = value': code earlier in the same straight run of code (see
  Cpu6502.straight_runs()) stored the value at the target, and nothing has
  overwritten it, or made it unknown (a JSR, or an indexed store), since.
  These lines can be satisfied in any order, by any register, with other
  instructions in between.
- 'a = value' (or 'x', 'y'): the register holds the value at the point the
  line applies to (see below).

The other lines are instructions, in the regex snippets' syntax (e.g. 'jsr
$ff6e | jmp $ff71', or 'lda #nn : sta zp1'), names and comments:

- With instruction lines, the pattern matches where they match, as a regex
  snippet does (see snippet6502.parse_snippet()), starting at an instruction
  in the traced code, and where its effect lines hold. Each effect line
  applies just before the instruction line that comes after it (or, after
  the last one, just after the match): its memory and registers are as they
  are then. So effect lines can be conditions on the lines of a regex
  snippet, e.g. 'a = $1f' before a 'jsr oswrch'. A match's instructions
  aren't matched again by the same pattern.
- Without, the pattern matches as soon as all its lines hold; or, if some
  lines are optional and not all of them hold, when the lines that do hold
  stop holding (an overwrite, a JSR or an indexed store, or the end of the
  run), if they're enough for a match.
- a name, not indented: names the next line, for SnippetHelper's methods
  (e.g. get_binary_location()): an effect line's location is that of the
  store, an instruction line's is its own (as in a regex snippet).
- '?' at the start of a line makes it optional. A match needs every effect
  line that isn't optional, and at least one effect line. (An optional
  instruction line is as in a regex snippet.)
- ';' starts a comment.

A target is an address ('$0206', zero page or absolute); a variable bound to
one of a list of addresses ('vec = $0200 | $0202'), which can be used once
like this; or the variable plus or minus a number ('vec+1'). A value is a
number ('$80'); a name ('nn1', 'bank'), which matches a known value, the
same wherever the name is used; or '?', which matches any value that's
stored, known or not.
"""

import collections
import itertools
import re

import classification
import snippet6502
import utils

_NAME = r"[A-Za-z_][A-Za-z_0-9]*"

# An effect line (after any '?'): '[target] = value' or 'a = value'
_EFFECT_LINE = re.compile(r"^\s+(\[(?P<target>[^\]]*)\]|(?P<reg>[axyAXY]))\s*=\s*(?P<value>.*?)\s*$")
_LABEL_LINE = re.compile(r"^(" + _NAME + r")\s*$")
_TARGET_BINDING = re.compile(r"^\s*(?P<var>" + _NAME + r")\s*=\s*(?P<choices>.+?)\s*$")
_TARGET_VARIABLE = re.compile(r"^\s*(?P<var>" + _NAME + r")\s*(?:(?P<sign>[+-])\s*(?P<offset>\S+))?\s*$")


def _strip_comment(line):
    return line.split(';')[0].rstrip()

def is_effect_pattern(text):
    """Whether the snippet's text is an effect pattern (it has an effect
    line), rather than a regex snippet."""
    for line in text.splitlines():
        line = _strip_comment(line)
        if line.startswith('?'):
            line = ' ' + line[1:]
        if _EFFECT_LINE.match(line):
            return True
    return False


class Line:
    """One effect line. kind is 'memory' or 'register'. For a memory line,
    address is the target (or None if it's a variable's), and var and
    offset the variable's name and offset. value is ('number', n), ('name',
    name) or ('any', None)."""

    def __init__(self, label, optional, kind, *, address=None, var=None, offset=0, reg=None, value=None):
        # (position is the group of the position in the pattern's regex
        # that the line applies to, if it has instruction lines)
        self.position = None
        self.label = label
        self.optional = optional
        self.kind = kind
        self.address = address
        self.var = var
        self.offset = offset
        self.reg = reg
        self.value = value


class EffectPattern:
    """A parsed effect pattern (see the module's docstring)."""

    is_effect = True

    def __init__(self, text):
        self.text = text
        self.lines = []
        self.variables = {}         # name: [addresses]

        # The instruction lines, as a regex snippet (None if there aren't
        # any), with a position (an empty group) before each instruction line
        # and at the end, which the effect lines before it apply to
        self.regex = None
        self.regex_labels = collections.defaultdict(list)
        whole = bytearray()
        group_number = 1
        waiting = []                # the effect lines waiting for a position
        pending_label = None

        def position():
            nonlocal group_number
            whole.extend(b"()")
            group = group_number
            group_number += 1
            for i in waiting:
                self.lines[i].position = group
            waiting.clear()
            return group

        for raw in text.splitlines():
            line = _strip_comment(raw)
            if not line.strip():
                continue
            m = _LABEL_LINE.match(line)
            if m:
                pending_label = m.group(1)
                continue
            optional = line.startswith('?')
            effect = _EFFECT_LINE.match(' ' + line[1:] if optional else line)
            if effect:
                self.lines.append(self._parse_effect(effect, pending_label, optional, raw))
                waiting.append(len(self.lines) - 1)
            else:
                group = position()
                if pending_label is not None:
                    self.regex_labels[pending_label].append((group, True))
                pattern, labels, group_number = snippet6502.parse_line(line, group_number)
                if pattern is None:
                    self._error("not an effect or an instruction", raw)
                whole.extend(pattern)
                for name, groups in labels.items():
                    self.regex_labels[name].extend(groups)
            pending_label = None
        if whole:
            position()
            if pending_label is not None:
                self.regex_labels[pending_label].append((group_number - 1, True))
            self.regex = re.compile(bytes(whole), re.DOTALL)
        if not self.lines:
            self._error("an effect pattern needs an effect line", "")
        for line in self.lines:
            if line.kind == 'register' and self.regex is None:
                self._error("a register line ('{0} = ...') needs an instruction line, to say where it applies".format(line.reg), "")
            if line.var is not None and line.var not in self.variables:
                self._error("the variable '{0}' isn't given its addresses (e.g. '[{0} = $70 | $72]')".format(line.var), "")
        self.labels = {line.label: i for i, line in enumerate(self.lines) if line.label is not None}

        # Each binding of the variables, with the address of each memory
        # line for it, and which lines of which bindings are at each address
        names = sorted(self.variables)
        self.bindings = [dict(zip(names, values)) for values in itertools.product(*(self.variables[n] for n in names))]
        self.targets = []           # [binding index][line index] -> address (None for a register line)
        self.index = collections.defaultdict(list)     # address -> [(binding index, line index)]
        for b, binding in enumerate(self.bindings):
            targets = []
            for i, line in enumerate(self.lines):
                if line.kind != 'memory':
                    targets.append(None)
                    continue
                address = line.address if line.var is None else binding[line.var] + line.offset
                if not 0 <= address < 0x10000:
                    self._error("the address {0} is outside memory".format(hex(address)), "")
                targets.append(address)
                self.index[address].append((b, i))
            self.targets.append(targets)

    def _error(self, message, line):
        utils.die("register_snippet(): {0}{1}".format(message, ": '{0}'".format(line.strip()) if line.strip() else ""))

    def _parse_value(self, text, raw):
        text = text.strip()
        if text == '?':
            return ('any', None)
        if re.match("^" + _NAME + "$", text):
            return ('name', text)
        try:
            return ('number', snippet6502.parse_integer(text))
        except (ValueError, IndexError):
            self._error("a value is a number, a name or '?'", raw)

    def _parse_effect(self, m, label, optional, raw):
        value = self._parse_value(m.group('value'), raw)
        if m.group('reg'):
            return Line(label, optional, 'register', reg=m.group('reg').lower(), value=value)
        target = m.group('target')
        binding = _TARGET_BINDING.match(target)
        if binding:
            var = binding.group('var')
            if var in self.variables:
                self._error("the variable '{0}' is given its addresses twice".format(var), raw)
            try:
                choices = [snippet6502.parse_integer(c) for c in binding.group('choices').split('|')]
            except (ValueError, IndexError):
                self._error("a variable's addresses are numbers separated by '|'", raw)
            self.variables[var] = choices
            return Line(label, optional, 'memory', var=var, offset=0, value=value)
        variable = _TARGET_VARIABLE.match(target)
        if variable and not re.match(r"^\s*[$&%0-9]", target):
            offset = 0
            if variable.group('sign'):
                try:
                    offset = snippet6502.parse_integer(variable.group('offset'))
                except (ValueError, IndexError):
                    self._error("a variable's offset is a number", raw)
                if variable.group('sign') == '-':
                    offset = -offset
            return Line(label, optional, 'memory', var=variable.group('var'), offset=offset, value=value)
        try:
            address = snippet6502.parse_integer(target)
        except (ValueError, IndexError):
            self._error("a target is an address, a variable with its addresses, or a variable plus or minus a number", raw)
        return Line(label, optional, 'memory', address=address, value=value)

    def __repr__(self):
        return "EffectPattern({0!r})".format(self.text)


class RegisterValue:
    """The value of a register that satisfies a register line, and the
    binary address of the immediate operand it was loaded from (e.g. the 'nn'
    of 'lda #nn'), or None."""

    __slots__ = ("value", "value_operand")

    def __init__(self, value, value_operand):
        self.value = value
        self.value_operand = value_operand


class EffectMatch:
    """A match of an effect pattern. satisfied is {line index: the
    MemoryWrite (memory lines) or RegisterValue (register lines)} for the lines
    that hold; writes is {line index: the MemoryWrite at the line's target
    when the match was found, whether or not the line holds} for the memory
    lines; values is {name: value}; anchor is the binary address where the
    instruction lines matched, and regex_match the match (or None if there
    are none)."""

    def __init__(self, pattern, binding_index, satisfied, values, writes, anchor, regex_match=None):
        self.regex_match = regex_match
        self.pattern = pattern
        self.binding_index = binding_index
        self.binding = pattern.bindings[binding_index]
        self.satisfied = satisfied
        self.values = values
        self.writes = writes
        self.anchor = anchor

    def key(self):
        """What identifies the match, from one tracing pass to the next."""
        stores = tuple(sorted((i, w.binary_addr) for i, w in self.satisfied.items() if self.pattern.lines[i].kind == 'memory'))
        return (self.binding_index, stores, self.anchor)

    def locations(self):
        """The binary addresses of the stores that satisfy its lines, and of
        the start of its instruction lines' match."""
        result = [w.binary_addr for i, w in self.satisfied.items() if self.pattern.lines[i].kind == 'memory']
        if self.anchor is not None:
            result.append(self.anchor)
        return result


def _evaluate(pattern, b, context, consumed):
    """The lines of binding b that hold, and the values of the names they
    give ({line index: write or value}, {name: value}). context(i) is the
    state that line i applies to: (known, registers), where known is
    {address: MemoryWrite} and registers the pessimistic state (or None).
    consumed is the stores already used by a match of this binding."""
    satisfied = {}
    values = {}
    for i, line in enumerate(pattern.lines):
        known, registers = context(i)
        if line.kind == 'memory':
            write = known.get(pattern.targets[b][i])
            if write is None or write.binary_addr in consumed:
                continue
            value = write.value
            result = write
        else:
            value = None if registers is None else registers[line.reg].value
            if value is None:
                continue
            result = RegisterValue(value, registers[line.reg].get_previous_load_imm_operand())
        kind, expected = line.value
        if kind == 'number':
            if value != expected:
                continue
        elif kind == 'name':
            if value is None:
                continue
            if expected in values and values[expected] != value:
                continue
            values[expected] = value
        satisfied[i] = result
    return satisfied, values

def _enough(pattern, satisfied):
    """Whether the lines that hold are enough for a match."""
    return len(satisfied) > 0 and all(i in satisfied for i, line in enumerate(pattern.lines) if not line.optional)

def _apply(known, write):
    """Update the known memory {address: MemoryWrite} with a write."""
    if write is not None:
        if write.target is None:
            known.clear()
        else:
            known[write.target] = write

def find_matches(cpu, pattern, bytes_array):
    """The EffectMatches of the pattern in the code, in order (using the
    CPU states, which must be up to date)."""
    matches = []
    memory_lines = [i for i, line in enumerate(pattern.lines) if line.kind == 'memory']

    def make_match(b, satisfied, values, context, anchor=None, consumed=(), regex_match=None):
        writes = {}
        for i in memory_lines:
            write = context(i)[0].get(pattern.targets[b][i])
            writes[i] = None if write is None or write.binary_addr in consumed else write
        matches.append(EffectMatch(pattern, b, satisfied, values, writes, anchor, regex_match))

    runs = list(cpu.straight_runs())
    if pattern.regex is not None:
        # Where each instruction is in the runs (run, index), and where the
        # address after it is
        where = {}
        for r, run in enumerate(runs):
            for k, binary_addr in enumerate(run):
                where[binary_addr] = (r, k)
        after = {}
        for r, run in enumerate(runs):
            for k, binary_addr in enumerate(run):
                end = binary_addr + classification.get_classification(binary_addr).length()
                after.setdefault(end, (r, k + 1))
        states = {}

        def state_at(position):
            """(known memory, registers) just before the instruction at the
            position (or just after the one that ends there)."""
            if position not in states:
                place = where.get(position, after.get(position))
                if place is None:
                    states[position] = ({}, None)
                else:
                    r, k = place
                    known = {}
                    for binary_addr in runs[r][:k]:
                        _apply(known, cpu.memory_write(binary_addr))
                    state = cpu.cpu_states[runs[r][k - 1]] if k > 0 else None
                    states[position] = (known, None if state is None else state.pessimistic)
            return states[position]

        for run in runs:
            skip_until = None
            for binary_addr in run:
                if skip_until is not None and binary_addr < skip_until:
                    continue
                m = pattern.regex.match(bytes_array, binary_addr)
                if m is None:
                    continue
                context = lambda i: state_at(m.start(pattern.lines[i].position))
                found = False
                for b in range(len(pattern.bindings)):
                    satisfied, values = _evaluate(pattern, b, context, ())
                    if _enough(pattern, satisfied):
                        make_match(b, satisfied, values, context, binary_addr, regex_match=m)
                        found = True
                if found and m.end() > binary_addr:
                    skip_until = m.end()
        return matches

    for run in runs:
        known = {}
        context = lambda i: (known, None)

        # The bindings with lines that hold, but not all of them (binding
        # index: (satisfied, values, known when last evaluated))
        live = {}
        consumed = collections.defaultdict(set)

        def close(b):
            satisfied, values, known_then = live.pop(b)
            if _enough(pattern, satisfied):
                make_match(b, satisfied, values, lambda i: (known_then, None), consumed=consumed[b])
                consumed[b].update(w.binary_addr for i, w in satisfied.items())

        for write in cpu.memory_writes(run):
            if write.target is None:
                for b in sorted(live):
                    close(b)
                known.clear()
                continue
            affected = sorted({b for b, i in pattern.index.get(write.target, ())})
            # An overwrite of a line that holds ends what was found so far
            for b in affected:
                if b in live and any(pattern.targets[b][i] == write.target for i in live[b][0]):
                    close(b)
            known[write.target] = write
            for b in affected:
                satisfied, values = _evaluate(pattern, b, context, consumed[b])
                if not satisfied:
                    live.pop(b, None)
                elif len(satisfied) == len(pattern.lines):
                    live.pop(b, None)
                    make_match(b, satisfied, values, context, consumed=consumed[b])
                    consumed[b].update(w.binary_addr for i, w in satisfied.items())
                else:
                    live[b] = (satisfied, values, dict(known))
        for b in sorted(live):
            close(b)
    return matches
