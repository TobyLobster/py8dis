from __future__ import print_function
import sys

import classification
import config
import utils

config.set_formatter(sys.modules[__name__])

explicit_a = False

_pending_assertions = {}

def set_output_filename(filename):
    # Irrelevant for xa, accepted for compatibility with beebasm.
    pass

def hex2(n):
    return "$%s" % utils.plainhex2(n)

def hex4(n):
    return "$%s" % utils.plainhex4(n)

def hex(n):
    if n <= 0xff:
        return hex2(n)
    else:
        return hex4(n)

def inline_label(name):
    return "%s" % name

def explicit_label(name, value, offset=None):
    return "%s = %s%s" % (name, value, "" if offset is None else "+%d" % offset)

# xa supports ";" as a comment prefix, but by default colons terminate ";"
# comments, so we use "//".
def comment_prefix():
    return "//"

def assert_expr(expr, value):
    _pending_assertions[expr] = value

def set_cmos(b):
    pass

def disassembly_start():
    return []

def code_start(start_addr, end_addr):
    return ["    * = %s\n" % hex4(start_addr)]

def code_end():
    return []

# TODO: PSEUDOPC NEEDS TWEAKING FOR XA OF COURSE
def pseudopc_start(dest, source, length):
    return [utils.force_case("!pseudopc %s {" % hex(dest))]

def pseudopc_end(dest, source, length):
    return ["}"]

def disassembly_end():
    result = []
    spa = sorted((str(expr), hex(value)) for expr, value in _pending_assertions.items())
    for expr, value in spa:
        result.append("%s %s != %s {" % (utils.force_case("!if"), expr, value))
        result.append('    %s "Assertion failed: %s == %s"' % (utils.force_case("!error"), expr, value))
        result.append("}")
    return result

# TODO: xa needs a "!" prefix on the *operand*
def abs_suffix():
    return "+2"

def byte_prefix():
    return utils.force_case("    .byt ")

def word_prefix():
    return utils.force_case("    .word ")

def string_prefix():
    return utils.force_case("    .asc ")

def string_chr(c):
    if utils.isprint(c) and chr(c) not in ("/", '"'):
        return chr(c)
    return None
