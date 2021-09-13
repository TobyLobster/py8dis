from __future__ import print_function
import collections

import config
import disassembly
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

    def finalise(self):
        pass

    def emit(self, addr): # todo: redundant?
        print("\n".join(self.as_string_list(addr)))

    def as_string_list(self, addr):
        result = []
        byte_prefix = formatter().byte_prefix()
        data = list(get_constant8(addr + i) for i in range(self._length))
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

    def finalise(self):
        pass

    def emit(self, addr): # todo: redundant?
        print("\n".join(self.as_string_list(addr)))

    def as_string_list(self, addr):
        # ENHANCE: This code is a messy copy and paste of Data's emit() function; it
        # should probably all be cleaned up and factored out.
        result = []
        data = list(get_constant16(addr + i) for i in range(0, self._length, 2))
        longest_item = max(len(x) for x in data)
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

    def finalise(self):
        pass

    def emit(self, addr): # TODO: redundant?
        print("\n".join(self.as_string_list(addr)))

    def as_string_list(self, addr):
        result = []
        prefix = formatter().string_prefix()
        s = prefix
        state = 0
        s_i = 0
        for i in range(self._length):
            c = memory[addr + i]
            if utils.isprint(c) and c != ord('"'):
                if state == 0:
                    s += '"'
                elif state == 2:
                    s += ', "'
                state = 1
                s += formatter().string_chr(c)
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


class Relocation(object): # TODO: !?!!
    def __init__(self, dest, source, length):
        assert length > 0
        self._dest = dest
        self._source = source
        self._length = length

    def is_mergeable(self):
        return False

    def length(self):
        return self._length

    def finalise(self):
        disassembly.ensure_addr_labelled(self._dest)
        disassembly.ensure_addr_labelled(self._dest + self._length)
        disassembly.ensure_addr_labelled(self._source)

    def emit(self, addr):
        # TODO: NEED TO SUPPORT !PSEUDOPC FOR ACME
        # TODO: BEEBASM SPECIFIC
        # TODO: IGNORES CASE FORCING
        # Source and destination here are the source and destination for the
        # move which created this Relocation object, so they're "reversed" from
        # the assembly output perspective.
        print("    skip %s-%s" % (disassembly.get_label(self._dest + self._length, addr), disassembly.get_label(self._dest, addr)))
        # We must do all the copyblock commands at the end to avoid any assumption
        # about the order separate blocks of code are assembled in.
        disassembly._final_commands.append("copyblock %s, %s, %s" % (disassembly.get_label(self._dest, addr), disassembly.get_label(self._dest + self._length, addr), disassembly.get_label(self._source, addr)))


def add_expression(addr, s):
    expressions[addr] = s

def get_expression(addr, expected_value):
    expression = expressions[addr]
    # ENHANCE: It would be good to at least try to evaluate "expression" and generate
    # an error if it doesn't match expected_value. In reality most expressions will
    # be fairly simple combinations of labels and basic integer arithmetic, mixed with
    # the < and > operators to get the low and high bytes of a 16-bit word.
    utils.check_expr(expression, expected_value)
    return expression

def get_constant8(addr):
    if addr not in expressions:
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
        n = 0
        while utils.isprint(memory[addr + n]):
            n += 1
    if n > 0:
        disassembly.add_classification(addr, String(n, False))
    return addr + n

# ENHANCE: A variant on this which considers the top-bit-set byte as part of the
# string might be useful. The if-ed out code to decompose the last character
# into a readable form would then potentially be useful too.
def stringhi(addr):
    initial_addr = addr
    while True:
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

def stringhiz(addr):
    initial_addr = addr
    while True:
        if memory[addr] == 0 or (memory[addr] & 0x80) != 0:
            break
        addr += 1
    if addr > initial_addr:
        disassembly.add_classification(initial_addr, String(addr - initial_addr, False))
    return addr

def autostring(min_length=3):
    assert min_length >= 2
    for (start_addr, end_addr) in config.disassembly_range():
        for i in range(0, (end_addr - min_length) - start_addr):
            if not disassembly.is_classified(start_addr + i,  min_length):
                n = 0
                while not disassembly.is_classified(start_addr + i + n, 1) and utils.isprint(memory[start_addr + i + n]):
                    n += 1
                if n >= min_length:
                    string(start_addr + i, n)


def finalise():
    for start_addr, end_addr in config.disassembly_range():
        addr = start_addr
        while addr < end_addr:
            if not disassembly.is_classified(addr, 1):
                disassembly.add_classification(addr, Byte(1))
            addr += disassembly.get_classification(addr).length()

        disassembly.merge_classifications(start_addr, end_addr)
        disassembly.split_classifications(start_addr, end_addr)
