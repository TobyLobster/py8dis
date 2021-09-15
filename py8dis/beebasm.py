from __future__ import print_function
import sys

import classification
import config
import disassembly # TODO!?
import utils

config.set_formatter(sys.modules[__name__])

output_filename = None

explicit_a = True

_pending_assertions = {}
_disassembly_start = ""
_code_end_addr = 0 # TODO: bit hacky

def set_output_filename(filename):
    global output_filename
    output_filename = filename

def hex2(n):
    return "&%s" % utils.plainhex2(n)

def hex4(n):
    return "&%s" % utils.plainhex4(n)

def hex(n):
    if n <= 0xff:
        return hex2(n)
    else:
        return hex4(n)

def inline_label(name):
    return ".%s" % name

def explicit_label(name, value, offset=None):
    return "%s = %s%s" % (name, value, "" if offset is None else "+%d" % offset)

def comment_prefix():
    return ";"

def assert_expr(expr, value):
    _pending_assertions[expr] = value

def set_cmos(b):
    global _disassembly_start
    if b:
        _disassembly_start = "    cpu 1\n\n"

def disassembly_start():
    return utils.force_case(_disassembly_start)

def code_start(start_addr, end_addr):
    global _code_end_addr
    _code_end_addr = end_addr
    return (utils.force_case(
        "    org %s\n" % hex4(start_addr) +
        "    guard %s\n" % hex4(end_addr)))

def code_end():
    return ""

def pseudopc_start(dest, source, length):
    result = []
    result.append(utils.force_case("    org %s" % hex(dest)))
    result.append(utils.force_case("    guard %s" % hex(dest + length)))
    return result

def pseudopc_end(dest, source, length):
    result = []
    # TODO: Use LazyString?
    result.append("    %s %s, %s, %s" % (utils.force_case("copyblock"), disassembly.get_label(dest, source), disassembly.get_label(dest + length, source), disassembly.get_label(source, source)))
    result.append("    %s %s, %s" % (utils.force_case("clear"), disassembly.get_label(dest, source), disassembly.get_label(dest + length, source)))
    result.append("    %s %s + (%s - %s)" % (utils.force_case("org"), disassembly.get_label(source, source), disassembly.get_label(dest + length, source), disassembly.get_label(dest, source)))
    result.append("    %s %s" % (utils.force_case("guard"), hex(_code_end_addr)))
    return result

def disassembly_end():
    s = "\n"
    if len(_pending_assertions) > 0:
        s += "\n".join(utils.force_case("    assert ") + "%s == %s" % (expr, hex(value)) for expr, value in sorted(_pending_assertions.items()))
        s += "\n\n"

    s += utils.force_case("save")
    if output_filename is None:
        s += " pydis_start, pydis_end"
    else:
        s += ' "%s", pydis_start, pydis_end' % output_filename
    return s + "\n"

def abs_suffix():
    return ""

def byte_prefix():
    return utils.force_case("    equb ")

def word_prefix():
    return utils.force_case("    equw ")

def string_prefix():
    return utils.force_case("    equs ")

def string_chr(c):
    return chr(c)
