"""Effect patterns (see py8dis/effectpattern.py), which match what code does
rather than the bytes of its instructions, on the code in
asm_to_create_test_binaries/effect_patterns.asm:

- a 'vector' (a word at &0300 or &0302) set to a known address, in any order,
  with any registers and other instructions between: its handler is traced
  and labelled, the loads become '#<handler1' and '#>handler1', and the code
  is commented. Both lines are optional, so a vector with only one byte set
  in a run (before a JSR, before a store of an unknown value, or before a
  label) is commented as half set;
- a call to 'print' (&209d) with a known value at &70 and X=5, anchored on
  the JSR, with an optional line for any store to &71;
- conditions on the lines of a sequence: two calls to 'write' (&209e), the
  first with A=22, the second with A known, with up to two instructions
  between them, however A is set."""

from commands import *
import snippets6502

load(0x2000, "orig/effect_patterns.orig", "6502", "902de504973829fb3c6ad2c6c7ecf24a")
label(0x209c, "subroutine")
label(0x209d, "print")
label(0x209e, "write")

def trace_vector_handler(p):
    # Before tracing: trace the handler, and name it
    if p.matched('lo') and p.matched('hi'):
        handler = p.value('lo_value') + 256 * p.value('hi_value')
        name = "handler_{0:04x}".format(handler)
        label(handler, name)
        p.entry(handler)

def comment_vector(p):
    # After tracing: comment the code, and write the bytes as the handler's
    vector = p.binding('vec')
    if p.matched('lo') and p.matched('hi'):
        handler = p.value('lo_value') + 256 * p.value('hi_value')
        name = "handler_{0:04x}".format(handler)
        text = "Set the vector at ${0:04x} to {1}".format(vector, name)
        for line, maker in (('lo', make_lo), ('hi', make_hi)):
            operand = p.store(line).value_operand
            if operand is not None:
                expr(movemanager.b2r(operand), maker(name))
    elif p.matched('lo'):
        hi = p.store('hi')
        text = "Set the low byte of the vector at ${0:04x} to ${1:02x}{2}".format(
            vector, p.value('lo_value'), "" if hi is None else " (the high byte isn't known)")
    else:
        text = "Set the high byte of the vector at ${0:04x} to ${1:02x}".format(vector, p.value('hi_value'))
    disassembly.comment_binary(p.get_start_loc(), text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

snippets6502.register_snippet(trace_vector_handler, comment_vector, """
lo
?   [vec = $0300 | $0302] = lo_value
hi
?   [vec+1] = hi_value
""")

def comment_print(p):
    text = "Print with {0} at &70, X=5".format(p.value('n'))
    if p.matched('flag'):
        text += ", and something at &71"
    disassembly.comment_binary(p.get_binary_location('call'), text, align=Align.INLINE, auto_generated=True)

snippets6502.register_snippet(None, comment_print, """
    [$70] = n
    x = 5
flag
?   [$71] = ?
call
    jsr $209d
""")

def comment_mode(p):
    # (Before the first of the instructions, including the loads of the
    # values the registers hold)
    disassembly.comment_binary(p.extent()[0], "Select mode {0}".format(p.value('mode')), indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    # The mode as a constant, where it's loaded
    if p.value_operand('mode_value') is not None:
        constant(p.value('mode'), "mode_{0}".format(p.value('mode')))
        expr(movemanager.b2r(p.value_operand('mode_value')), "mode_{0}".format(p.value('mode')))

snippets6502.register_snippet(None, comment_mode, """
    a = 22
    jsr $209e
?   .
?   .
mode_value
    a = mode
    jsr $209e
""")

entry(0x2000, "start")
go()
