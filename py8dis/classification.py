from __future__ import print_function
import collections

import config
import disassembly
import labelmanager
import utils
import trace

expressions = {}
memory = config.memory
formatter = config.formatter

# ENHANCE: At the moment there's no support for wrapping round at the top of
# memory and we might just crash (probably with an out-of-bounds error) if
# disassembling right up to the top of memory.

class Byte(object):
    def __init__(self, length, is_mergeable=True):
        assert length > 0
        self._length = length
        self._is_mergeable = is_mergeable

    def is_mergeable(self):
        return self._is_mergeable

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        self._length = length

    def is_code(self, addr):
        return False

    def as_string_list(self, addr):
        result = []
        byte_prefix = formatter().byte_prefix()
        data = list(get_constant8(addr + i, True) for i in range(self._length))
        def asciify(n):
            if n in expressions:
                return "."
            c = memory[n]
            if utils.isprint(c):
                return chr(c)
            return "."
        ascii = list(asciify(addr + i) for i in range(self._length))
        longest_item = max(len(x) for x in data)
        available_width = config.inline_comment_column() - len(byte_prefix)
        items_per_line = min(max(1, available_width // (longest_item + 2)), 8)
        item_min_width = min(longest_item, available_width // items_per_line)
        #print("QQ", longest_item, items_per_line, item_min_width)
        #print("QQ2", ascii)
        directives = []
        comments = []
        for chunk in utils.chunks(data, items_per_line):
            s = ""
            sep = ""
            for item in chunk:
                s += sep + "%-*s" % (item_min_width, item)
                sep = ", "
            directives.append("%s%s" % (byte_prefix, s))
        i = 0
        for chunk in utils.chunks(ascii, items_per_line):
            comments.append(("%s %s: " % (formatter().comment_prefix(), utils.plainhex4(addr+i))) + "".join(chunk))
            i += len(chunk)
        comment_indent = config.inline_comment_column()
        for directive, comment in zip(directives, comments):
            if config.bytes_as_ascii():
                result.append("%-*s%s" % (comment_indent, directive, comment))
            else:
                result.append(directive)
        return result


class Word(object):
    def __init__(self, length, is_mergeable=True):
        self.set_length(length)
        self._is_mergeable = is_mergeable

    def is_mergeable(self):
        return self._is_mergeable

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        assert length % 2 == 0
        self._length = length

    def is_code(self, addr):
        return False

    def as_string_list(self, addr):
        # ENHANCE: This code is a messy copy and paste of Data's emit() function; it
        # should probably all be cleaned up and factored out.
        result = []
        data = list(get_constant16(addr + i) for i in range(0, self._length, 2))
        longest_item = 10 # TODO: hack, was: max(len(x) for x in data)
        available_width = config.inline_comment_column() - 10
        items_per_line = min(max(1, available_width // (longest_item + 2)), 8)
        item_min_width = min(longest_item, available_width // items_per_line)
        i = 0
        for chunk in utils.chunks(data, items_per_line):
            s = ""
            sep = ""
            for item in chunk:
                s += sep + "%-*s" % (item_min_width, item)
                sep = ", "
            result.append(utils.add_hex_dump("%s%s" % (formatter().word_prefix(), s), addr + i, len(chunk) * 2))
            i += len(chunk)
        return result


class String(object):
    def __init__(self, length, is_mergeable=True):
        assert length > 0
        self._length = length
        self._is_mergeable = is_mergeable

    def is_mergeable(self):
        return self._is_mergeable

    def length(self):
        return self._length

    def set_length(self, length):
        assert length > 0
        self._length = length

    def is_code(self, addr):
        return False

    def as_string_list(self, addr):
        result = []
        prefix = formatter().string_prefix()
        s = prefix
        state = 0
        s_i = 0
        for i in range(self._length):
            c = memory[addr + i]
            c_in_string = formatter().string_chr(c)
            if c_in_string is not None:
                if state == 0:
                    s += '"'
                elif state == 2:
                    s += ', "'
                state = 1
                s += c_in_string
            else:
                if state == 1:
                    s += '", '
                elif state == 2:
                    s += ", "
                state = 2
                if c == ord('"'):
                    s += "'\"'"
                else:
                    s += get_constant8(addr + i)
            if len(s) > (config.inline_comment_column() - 5):
                if state == 1:
                    s += '"'
                result.append(utils.add_hex_dump(s, addr + s_i, i - s_i))
                s = prefix
                s_i = i + 1
                state = 0
        if s != prefix:
            if state == 1:
                s += '"'
            result.append(utils.add_hex_dump(s, addr + s_i, self._length - s_i))
        return result


def add_expression(addr, s):
    assert not isinstance(s, labelmanager.Label) # TODO!?
    # TODO: Warn/assert if addr already in expressions? Allow overriding this via an optional bool argument?
    if addr not in expressions:
        expressions[addr] = s

def get_expression(addr, expected_value):
    expression = expressions[addr]
    # TODO: Possibly a bit hacky, feeling my way here during refactor - what I believe we're trying to do is avoid doing check_expr() for simple labels, but we are also working round the fact that if expression *is* a Label object it can't be used like a (lazy)string which other expressions are - so we have a kind of internal inconsistency here which it would be nice not to have to hack round - perhaps the problem is that Label objects are leaking out to somewhere where they are then being passed by back to add_expression and we should work with (lazy)strings more consistently?? - I am leaning towards trying this, perhaps with (not immediately essential) making an effort to return simple strings if a function has (for example) been *given* a label as a string. Note that you can't "just" string-ise a Label in isolation, as you need an address to give it context, so whatever object we use as a "label-ish" thing has to contain that context (which LazyStrings can, because they can contain a get_label() call with addr and context)
    if isinstance(expression, labelmanager.Label):
        assert False
        return expression # TODO TEMP EXP - this breaks things but I wanted to see how
        return disassembly.get_label(expression.addr, addr, None)

    # ENHANCE: It would be good to at least try to evaluate "expression" and generate
    # an error if it doesn't match expected_value. In reality most expressions will
    # be fairly simple combinations of labels and basic integer arithmetic, mixed with
    # the < and > operators to get the low and high bytes of a 16-bit word.
    utils.check_expr(expression, expected_value)
    return expression

def get_constant8(addr, force_hex2=False):
    if addr not in expressions:
        if memory[addr] < 10 and not force_hex2:
            return "%d" % memory[addr]
        return formatter().hex2(memory[addr])
    return get_expression(addr, memory[addr])

def get_constant16(addr):
    if addr not in expressions:
        return formatter().hex4(utils.get_u16(addr))
    return get_expression(addr, utils.get_u16(addr))

def get_address8(addr):
    operand = memory[addr]
    if addr not in expressions:
        return disassembly.get_label(operand, addr)
    return get_expression(addr, operand)

def get_address16(addr):
    operand = utils.get_u16(addr)
    if addr not in expressions:
        return disassembly.get_label(operand, addr)
    assert isinstance(disassembly.get_classification(addr), Word)
    return get_expression(addr, operand)

def stringterm(addr, terminator, exclude_terminator=False):
    initial_addr = addr
    while True:
        if memory[addr] == terminator:
            break
        addr += 1
    string_length = (addr + 1) - initial_addr
    if exclude_terminator:
        string_length -= 1
    if string_length > 0:
        disassembly.add_classification(initial_addr, String(string_length, False))
    return addr + 1

def stringcr(addr, exclude_terminator=False):
    return stringterm(addr, 13, exclude_terminator)

def stringz(addr, exclude_terminator=False):
    return stringterm(addr, 0, exclude_terminator)

def string(addr, n=None):
    if n is None:
        assert not disassembly.is_classified(addr)
        n = 0
        while not disassembly.is_classified(addr + n) and utils.isprint(memory[addr + n]):
            n += 1
    if n > 0:
        disassembly.add_classification(addr, String(n, False))
    return addr + n

# ENHANCE: A variant on this which considers the top-bit-set byte as part of the
# string might be useful. The if-ed out code to decompose the last character
# into a readable form would then potentially be useful too.
def stringhi(addr):
    assert not disassembly.is_classified(addr, 1)
    initial_addr = addr
    while True:
        if disassembly.is_classified(addr, 1):
            break
        if memory[addr] & 0x80 != 0:
            if False: # ENHANCE: Works but not that helpful so save it for a case where it is
                c = memory[addr] & 0x7f
                if utils.isprint(c) and c != ord('"'):
                    add_expression(addr, "%s+'%s'" % (formatter().hex2(0x80), chr(c)))
            break
        addr += 1
    if addr > initial_addr:
        disassembly.add_classification(initial_addr, String(addr - initial_addr, False))
    return addr

# Behaviour with include_terminator_fn=None should be beebdis-compatible.
def stringhiz(addr, include_terminator_fn=None):
    assert not disassembly.is_classified(addr, 1)
    initial_addr = addr
    while True:
        if disassembly.is_classified(addr, 1):
            break
        if memory[addr] == 0 or (memory[addr] & 0x80) != 0:
            if include_terminator_fn is not None and include_terminator_fn(memory[addr]):
                addr += 1
            break
        addr += 1
    if addr > initial_addr:
        disassembly.add_classification(initial_addr, String(addr - initial_addr, False))
    return addr

def stringn(addr):
    disassembly.add_classification(addr, Byte(1, False))
    length = memory[addr]
    add_expression(addr, utils.LazyString("%s - %s", disassembly.get_label(addr + 1 + length, addr), disassembly.get_label(addr + 1, addr)))
    return string(addr + 1, length)

def autostring(min_length=3):
    assert min_length >= 2
    addr = 0
    while addr < len(memory):
        i = 0
        while (addr + i) < len(memory) and memory[addr + i] is not None and not disassembly.is_classified(addr + i, 1) and utils.isprint(memory[addr + i]):
            i += 1
            if (addr + i) in labelmanager.labels:
                break
        if i >= min_length:
            string(addr, i)
        addr += max(1, i)

def classify_leftovers():
    # TODO: Might be able to factor out common code with autostring()
    addr = 0
    while addr < len(memory):
        i = 0
        while (addr + i) < len(memory) and memory[addr + i] is not None and not disassembly.is_classified(addr + i, 1):
            i += 1
            if (addr + i) in labelmanager.labels:
                break
        if i > 0:
            disassembly.add_classification(addr, Byte(i, False))
        addr += max(1, i)
