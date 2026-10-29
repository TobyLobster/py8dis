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
- 'a = value' (or 'x', 'y'): the register holds the value just before the
  anchor.

The other lines are:

- the anchor: an instruction line, in the regex snippets' syntax (e.g.
  'jsr $ff6e | jmp $ff71'). There can be at most one. With an anchor, the
  pattern matches at each instruction that matches it where the other lines
  hold just before it. Without one, the pattern matches as soon as all its
  lines hold; or, if some lines are optional and not all of them hold, when
  the lines that do hold stop holding (an overwrite, a JSR or an indexed
  store, or the end of the run), if they're enough for a match.
- a name, not indented: names the next line, for SnippetHelper's methods
  (e.g. get_binary_location()): an effect line's location is that of the
  store, the anchor's is the anchor's.
- '?' at the start of a line makes it optional. A match needs every line
  that isn't optional, and at least one line.
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
        self.anchor = None          # a compiled regex for the anchor's bytes
        self.anchor_label = None
        self.anchor_regex_labels = None
        self.variables = {}         # name: [addresses]
        pending_label = None
        for raw in text.splitlines():
            line = _strip_comment(raw)
            if not line.strip():
                continue
            m = _LABEL_LINE.match(line)
            if m:
                pending_label = m.group(1)
                continue
            optional = line.startswith('?')
            if optional:
                line = ' ' + line[1:]
            m = _EFFECT_LINE.match(line)
            if m:
                self.lines.append(self._parse_effect(m, pending_label, optional, raw))
            else:
                if self.anchor is not None:
                    self._error("an effect pattern can have only one instruction line (its anchor)", raw)
                if optional:
                    self._error("the anchor can't be optional", raw)
                pattern, labels, _ = snippet6502.parse_line(line, 1)
                if pattern is None:
                    self._error("not an effect or an instruction", raw)
                self.anchor = re.compile(bytes(pattern), re.DOTALL)
                self.anchor_label = pending_label
            pending_label = None
        if not self.lines:
            self._error("an effect pattern needs an effect line", "")
        for line in self.lines:
            if line.kind == 'register' and self.anchor is None:
                self._error("a register line ('{0} = ...') needs an anchor (an instruction line)".format(line.reg), "")
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


class EffectMatch:
    """A match of an effect pattern. satisfied is {line index: the
    MemoryWrite (memory lines) or the value (register lines)} for the lines
    that hold; writes is {line index: the MemoryWrite at the line's target
    when the match was found, whether or not the line holds} for the memory
    lines; values is {name: value}; anchor is the anchor's binary address,
    if there is one."""

    def __init__(self, pattern, binding_index, satisfied, values, writes, anchor):
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
        the anchor."""
        result = [w.binary_addr for i, w in self.satisfied.items() if self.pattern.lines[i].kind == 'memory']
        if self.anchor is not None:
            result.append(self.anchor)
        return result


def _evaluate(pattern, b, known, consumed, registers):
    """The lines of binding b that hold, and the values of the names they
    give ({line index: write or value}, {name: value}). known is {address:
    MemoryWrite}, consumed the stores already used by a match of this
    binding, and registers the pessimistic state before the anchor (or
    None)."""
    satisfied = {}
    values = {}
    for i, line in enumerate(pattern.lines):
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
            result = value
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

def find_matches(cpu, pattern, bytes_array):
    """The EffectMatches of the pattern in the code, in order (using the
    CPU states, which must be up to date)."""
    matches = []
    memory_lines = [i for i, line in enumerate(pattern.lines) if line.kind == 'memory']

    def make_match(b, satisfied, values, known, anchor=None, consumed=()):
        writes = {}
        for i in memory_lines:
            write = known.get(pattern.targets[b][i])
            writes[i] = None if write is None or write.binary_addr in consumed else write
        matches.append(EffectMatch(pattern, b, satisfied, values, writes, anchor))

    for run in cpu.straight_runs():
        known = {}
        if pattern.anchor is not None:
            registers = None
            for binary_addr in run:
                if pattern.anchor.match(bytes_array, binary_addr):
                    for b in range(len(pattern.bindings)):
                        satisfied, values = _evaluate(pattern, b, known, (), registers)
                        if _enough(pattern, satisfied):
                            make_match(b, satisfied, values, known, binary_addr)
                write = cpu.memory_write(binary_addr)
                if write is not None:
                    if write.target is None:
                        known.clear()
                    else:
                        known[write.target] = write
                state = cpu.cpu_states[binary_addr]
                registers = None if state is None else state.pessimistic
            continue

        # Without an anchor: the bindings with lines that hold, but not all
        # of them (binding index: (satisfied, values, known when last
        # evaluated))
        live = {}
        consumed = collections.defaultdict(set)

        def close(b):
            satisfied, values, known_then = live.pop(b)
            if _enough(pattern, satisfied):
                make_match(b, satisfied, values, known_then, consumed=consumed[b])
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
                satisfied, values = _evaluate(pattern, b, known, consumed[b], None)
                if not satisfied:
                    live.pop(b, None)
                elif len(satisfied) == len(pattern.lines):
                    live.pop(b, None)
                    make_match(b, satisfied, values, known, consumed=consumed[b])
                    consumed[b].update(w.binary_addr for i, w in satisfied.items())
                else:
                    live[b] = (satisfied, values, dict(known))
        for b in sorted(live):
            close(b)
    return matches
