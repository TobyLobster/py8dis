"""
Snippets (6502)

Snippets recognise common pieces of 6502 code or data (e.g. a loop that
copies memory) and comment them, name things in them, or trace the code they
lead to (see docs/snippets-and-hooks.md). This module has the functions for
registering a snippet (register_snippet() and the shortcuts after it), and
the built in snippets, which are registered at the end of the file.

A snippet is described by its text, which is one of:
- a regex snippet: lines of 6502 assembly in which a name matches any value
  (see snippet6502.parse_snippet()), matched as a regular expression on the
  binary's bytes;
- an effect pattern: what the code does, e.g. the values it stores (see
  effectpattern.py), matched using the CPU states.
parse_snippet() works out which it is. A registered snippet is a
snippethelper.SnippetDetails: the parsed pattern, and the functions to call
for each match, before and after tracing.

How a regex snippet is matched (see Cpu.trace() in cpu.py, and
pre_trace_with_regex() and post_trace_with_regex() in cpu6502.py):
- Before tracing is finished: once the code has been traced from the entry
  points given, py8dis searches all the loaded bytes (not just the code
  found so far) for each snippet in turn, in the order they were
  registered, and calls its pre-trace function for each match. That can add
  entry points (p.entry()), which are traced before the next match is
  looked at, so a match that starts inside an instruction found that way is
  rejected (see snippethelper.SnippetRejected).
- After tracing and the code analysis, when the CPU states (what's known of
  the registers at each instruction) and the references to each label are
  known, it searches again and calls each post-trace function, which can
  use them, e.g. to say how many bytes a loop copies.
In each search, a match that overlaps an earlier match (of this snippet or
an earlier one) is skipped. Each function is given a
snippethelper.SnippetHelper ('p'), which says where each name in the
snippet matched. A function can also be a string, which is added as an
inline comment at the start of each match.

Effect patterns are matched once the CPU states are known, and again after
each time the entry points they add are traced (see
find_entry_points_from_effects() in cpu6502.py). Their functions are given
a snippethelper.EffectHelper.

Only the 6502 family (cpu6502.py and the CPUs derived from it) uses
snippets. The built in ones are in BUILTIN_SNIPPETS; each session's list of
snippets starts as a copy of it (see session.py), and machine modules such
as acorn.py and commodore.py, and control files, add their own.
"""

import classification
import disassembly
import effectpattern
import snippet6502
import utils
import labelmanager
import session
import sys
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from snippethelper import *

# Opcodes the snippets' functions look for in a match's bytes, e.g. to tell
# which branch or which register a loop uses
OPCODE_LDA_ZP_COMMA_X           = 0xb5      # lda zp,x
OPCODE_STA_ZP_COMMA_X           = 0x95      # sta zp,x
OPCODE_DEX                      = 0xca      # dex
OPCODE_INX                      = 0xe8      # inx
OPCODE_BNE                      = 0xd0      # bne loop
OPCODE_BCC                      = 0x90      # bcc loop
OPCODE_TXA                      = 0x8a      # txa
OPCODE_TYA                      = 0x98      # tya

# The built in snippets (SnippetDetails, see the module docstring), registered
# at the end of this file when it's first imported. The snippets in use are
# the session's 'snippets' list (see session.py), which starts as a copy of
# these. After that, the register_*() functions add to it.
BUILTIN_SNIPPETS = []

# True while this module is registering the built in snippets, when it's first
# imported
_registering_builtins = True

def _add(details):
    """Add a snippet (a SnippetDetails): to BUILTIN_SNIPPETS while this
    module registers the built in ones, otherwise to the current session's
    snippets."""
    if _registering_builtins:
        BUILTIN_SNIPPETS.append(details)
    else:
        session.current().snippets.append(details)

# ************************************************************************************************
def add_entry(p):
    """A pre-trace function: trace the match as code, from its start (or
    reject it if it can't be code there, see SnippetHelper.entry())."""
    p.entry()

def add_code_comment(p, comment):
    """A pre-trace function (with the comment as its parameter): trace the
    match as code, as add_entry() does, and comment its start with the text,
    on a line of its own after any label."""
    p.entry()
    disassembly.comment_binary(p.get_start_loc(), comment, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

def add_data_comment(p, comment):
    """A pre-trace function (with the comment as its parameter): comment the
    start of the match inline (at the end of its line), without tracing
    it."""
    disassembly.comment_binary(p.get_start_loc(), comment, align=Align.INLINE, auto_generated=True)


def parse_snippet(snippet):
    """The snippet's text, parsed: a regex snippet (snippet6502.Snippet) or,
    if it has an effect line (see effectpattern.is_effect_pattern()), an
    effect pattern (effectpattern.EffectPattern)."""
    if effectpattern.is_effect_pattern(snippet):
        return effectpattern.EffectPattern(snippet)
    return snippet6502.parse_snippet(snippet)

def register_snippet(pre_trace_fn, post_trace_fn, snippet):
    """Register a snippet: a regex snippet (see snippet6502.parse_snippet())
    or an effect pattern (see effectpattern.py), with the functions to call
    for each match, before and after tracing (or None). Each is called with
    the match's SnippetHelper (an EffectHelper for an effect pattern), or
    can be a string, which is added as an inline comment at the start of
    each match.

    For a regex snippet, the pre-trace function is called for each match in
    the loaded bytes once the code from the entry points given has been
    traced (it can add entry points, or reject the match), and the
    post-trace function for each match once the code is traced and analysed
    (for comments and expressions). For an effect pattern, the pre-trace
    function is called once for each match found while tracing (it can add
    entry points and labels), and the post-trace function once for each
    match in the code as finally traced, after the code has been analysed
    (for comments and expressions). See the module docstring."""
    _add(SnippetDetails(pre_trace_fn, None, post_trace_fn, None, parse_snippet(snippet)))

def register_code_snippet(post_trace_fn, snippet):
    """Register a snippet for code: before tracing, each match is traced as
    code (see add_entry()), and after tracing post_trace_fn(p) is called
    for it (unless it's None)."""
    _add(SnippetDetails(add_entry, None, post_trace_fn, None, parse_snippet(snippet)))

def register_data_snippet(post_trace_fn, snippet):
    """Register a snippet for data: the matches aren't traced, and after
    tracing post_trace_fn(p) is called for each (e.g. to classify and
    comment a table)."""
    _add(SnippetDetails(None, None, post_trace_fn, None, parse_snippet(snippet)))

def register_comment_code_snippet(comment, snippet):
    """Register a snippet for code that just needs a comment: before
    tracing, each match is traced as code and its start commented with the
    text (see add_code_comment())."""
    _add(SnippetDetails(add_code_comment, comment, None, None, parse_snippet(snippet)))

def register_comment_data_snippet(comment, snippet):
    """Register a snippet for data that just needs a comment: before
    tracing, the start of each match is commented inline with the text, and
    it isn't traced (see add_data_comment())."""
    _add(SnippetDetails(add_data_comment, comment, None, None, parse_snippet(snippet)))

# ************************************************************************************************
# The bytes a loop works on, from its index register's values

def _loop_indices(start, step, keep_going):
    """The values of a loop's index register in each pass, as a list: from
    'start', adding 'step' (1 or -1, for INX or DEX etc.) after each pass,
    wrapping round within a byte, while keep_going(the new value) is True
    (the loop's branch back). None if the loop doesn't end within 256
    passes (e.g. 'dex : cpx #0 : bcs loop', since CPX #0 always sets the
    carry)."""
    values = []
    value = start
    for _ in range(256):
        values.append(value)
        value = (value + step) & 0xff
        if not keep_going(value):
            return values
    return None

def _loop_run(start, step, keep_going):
    """The bytes a loop indexes (see _loop_indices()), as (the lowest index,
    the number of bytes), or None if the loop doesn't end, or the bytes
    aren't one run (e.g. a count up that wraps round from 255 to 0, so the
    bytes are at both ends of the 256 the register can index)."""
    values = _loop_indices(start, step, keep_going)
    if values is None:
        return None
    lowest = min(values)
    if sorted(values) != list(range(lowest, lowest + len(values))):
        return None
    return lowest, len(values)

# ************************************************************************************************
def comment_memory_copy_loop(p):
    """Post-trace function for a loop that copies memory, counting X or Y
    down to zero ('dex : bne loop') or past it ('dex : bpl loop'): comment
    it, e.g. 'Copy 8 bytes of memory from source to dest'.

    The count is the register's value before the loop: from the CPU state
    after the snippet's first instruction (the LDX or LDY, if there is one),
    or failing that the LDX or LDY's operand. With BNE, a count of N copies
    the N bytes from addr+1 to addr+N, and a count of 0 the 256 from addr.
    With BPL, it copies the N+1 bytes from addr, or for a count of 129 or
    more just the one at addr+N (the first DEX or DEY then leaves the
    register negative). The source and destination are named by the label
    for the lowest byte copied, and if that isn't addr, the operands are
    written as that label minus the difference. If the count isn't known,
    the comment gives it in terms of the register (e.g. 'X bytes', from
    addr+1, for BNE). An indirect load or
    store (e.g. '(zp1),y') isn't named. Nothing is commented if the branch
    doesn't go back to the loop's start."""

    # Make sure the branch instruction's operand jumps to the definition of the label
    if not p.check_branch_matches('loop'):
        return

    # Get loop initial value, look at known register state
    comment_loc         = p.get_start_loc()
    is_load_indirect    = p.get_memory('zp1')   # This is treated as a flag, being None if 'zp1' isn't found
    is_store_indirect   = p.get_memory('zp2')   # This is treated as a flag, being None if 'zp2' isn't found
    is_stop_at_zero     = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL
    offset              = 1 if is_stop_at_zero else 0
    source_label        = ""
    dest_label          = ""
    reg                 = 'x' if p.get_memory('update') == OPCODE_DEX else 'y'
    state               = p.get_state('comment')
    bytes_to_copy       = state.pessimistic[reg].value if state and state.pessimistic[reg] else None
    if bytes_to_copy is None:
        bytes_to_copy = p.get_memory("start_count")

    # The lowest byte copied, and how many: the loop goes on while the
    # register isn't zero (BNE), or isn't negative (BPL). (Without a known
    # count, it's taken to start above zero.)
    if bytes_to_copy is not None:
        run = _loop_run(bytes_to_copy, -1, (lambda r: r != 0) if is_stop_at_zero else (lambda r: r < 0x80))
        if run is None:
            return
        offset, bytes_to_copy = run

    # Name the source by the lowest byte copied (addr+offset). With an offset,
    # the load's operand (the byte after its opcode) is written as that label
    # minus the offset, unless it already has an expression, when the source
    # is that expression plus the offset.
    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = p.make_subtract_wrapped(source_label, 'addr', offset)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                source_label = make_add(new_expression, offset)
        source_label = utils.LazyString(" from %s", source_label)

    # The same for the destination
    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=offset)

        if offset:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = p.make_subtract_wrapped(dest_label, 'other', offset)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                dest_label = make_add(new_expression, offset)
        dest_label = utils.LazyString(" to %s", dest_label)

    # If the count isn't known, what to add to the register's name: "X+1"
    # for BPL
    offset_string = "+1" if bytes_to_copy is None and not is_stop_at_zero else ""

    if bytes_to_copy is not None:
        bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte of memory", "bytes of memory")
    else:
        bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_memory_copy_with_limited_end_loop(p):
    """Post-trace function for a loop that copies memory, counting X or Y
    down to a limit ('dey : cpy #end_count : bcs loop'): comment it as
    comment_memory_copy_loop() does, e.g. 'Copy 8 bytes of memory from
    source to dest'. The loop copies from start_count down to end_count (or
    just start_count, if that's below end_count), so the source and
    destination are named by the label for the lowest byte copied, and the
    operands are written as that minus its offset from addr. Nothing is
    commented if the branch doesn't go back to the loop's start, if the
    loop never ends (end_count is zero), or if the bytes aren't one run (a
    start_count of zero wraps round to 255, so the loop copies at 0 and then
    from 255 down)."""

    # Make sure the branch instruction's operand jumps to the definition of the label
    if not p.check_branch_matches('loop'):
        return

    # Get loop initial value, look at known register state
    comment_loc         = p.get_start_loc()
    is_load_indirect    = p.get_memory('zp1')   # This is treated as a flag, being None if 'zp1' isn't found
    is_store_indirect   = p.get_memory('zp2')   # This is treated as a flag, being None if 'zp2' isn't found
    is_stop_at_zero     = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL
    end_count           = p.get_memory('end_count')
    source_label        = ""
    dest_label          = ""
    reg                 = 'x' if p.get_memory('update') == OPCODE_DEX else 'y'
    state               = p.get_state('comment')
    start_count         = state.pessimistic[reg].value if state and state.pessimistic[reg] else None
    if start_count is None:
        start_count = p.get_memory("start_count")

    # 'cpx #0' always sets the carry, so with an end_count of zero the loop never
    # ends. That's not a memory copy.
    if end_count == 0:
        return

    # The lowest byte copied (offset), and how many: the loop goes on while
    # the register is at least end_count (BCS, after CPX or CPY). (Without a
    # known start_count, the lowest is taken to be end_count.)
    offset = end_count
    bytes_to_copy = None
    if start_count is not None:
        run = _loop_run(start_count, -1, lambda r: r >= end_count)
        if run is None:
            return
        offset, bytes_to_copy = run

    # Name the source by the lowest byte copied (addr+offset), with the
    # load's operand written as that label minus the offset, unless it
    # already has an expression, when the source is that expression plus the
    # offset
    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = p.make_subtract_wrapped(source_label,'addr',offset)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                source_label = make_add(new_expression, offset)
        source_label = utils.LazyString(" from %s", source_label)

    # The same for the destination
    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=offset)

        if offset:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = p.make_subtract_wrapped(dest_label, 'other', offset)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                dest_label = make_add(new_expression, offset)
        dest_label = utils.LazyString(" to %s", dest_label)

    # If start_count isn't known, the number of bytes is the initial value of
    # the register minus (end_count - 1)
    offset_string = "" if end_count == 1 else "-%d" % (end_count - 1)

    if bytes_to_copy is not None:
        bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte of memory", "bytes of memory")
    else:
        bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)


# ************************************************************************************************
def comment_memory_copy_increment(p):
    """Post-trace function for a loop that copies memory, counting X or Y
    up to a limit ('inx : cpx #end_count : bne loop', or BCC): comment it
    as comment_memory_copy_loop() does, e.g. 'Copy 8 bytes of memory from
    source to dest'. The loop copies end_count - start_count bytes from
    addr+start_count (or with BCC, just the one at start_count if that's
    at least end_count), so the source and destination are named by the
    label for that address, and the operands are written as that minus
    start_count. Nothing is commented if the branch doesn't go back to the
    loop's start, if start_count isn't known, or if the bytes aren't one
    run (the register wraps round from 255 to 0, e.g. 'ldx #$f0 ... cpx
    #$10 : bne loop')."""

    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    # Get loop initial value, look at known register state
    comment_loc         = p.get_start_loc()
    is_load_indirect    = p.get_memory('zp1')   # This is treated as a flag, being None if 'zp1' isn't found
    is_store_indirect   = p.get_memory('zp2')   # This is treated as a flag, being None if 'zp2' isn't found
    end_count           = p.get_memory('end_count')
    source_label        = ""
    dest_label          = ""
    reg                 = 'x' if p.get_memory('update') == OPCODE_INX else 'y'
    is_bcc              = p.get_memory('branch') == OPCODE_BCC      # BCC or BNE
    state               = p.get_state('comment')
    start_count         = state.pessimistic[reg].value if state and state.pessimistic[reg] else None
    if start_count is None:
        start_count = p.get_memory("start_count")
        if start_count is None:
            return

    # The first byte copied, and how many: the loop goes on while the
    # register is below end_count (BCC, after CPX or CPY), or isn't
    # end_count (BNE)
    run = _loop_run(start_count, 1, (lambda r: r < end_count) if is_bcc else (lambda r: r != end_count))
    if run is None:
        return
    start_count, bytes_to_copy = run

    # Name the source by the first byte copied (addr+start_count), with the
    # load's operand written as that label minus start_count, unless it
    # already has an expression, when the source is that expression plus
    # start_count
    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=start_count)

        source_binary_addr = p.get_binary_address('load')+1
        proposed_expression = p.make_subtract_wrapped(source_label, 'addr', start_count)
        new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
        if new_expression is not None and new_expression != proposed_expression:
            source_label = make_add(new_expression, start_count)
        source_label = utils.LazyString(" from %s", source_label)

    # The same for the destination
    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=start_count)

        dest_binary_addr = p.get_binary_address('store')+1
        proposed_expression = p.make_subtract_wrapped(dest_label, 'other', start_count)
        new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
        if new_expression is not None and new_expression != proposed_expression:
            dest_label = make_add(new_expression, start_count)
        dest_label = utils.LazyString(" to %s", dest_label)

    bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte of memory", "bytes of memory")

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_add_to_y(p):
    """Post-trace function for 'tya : clc : adc #nn : tay': comment it 'add
    nn to Y' (nn in decimal)."""
    disassembly.comment_binary(p.get_start_loc(), "add {0} to Y".format(p.get_memory("nn")), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_add_to_x(p):
    """Post-trace function for 'txa : clc : adc #nn : tax': comment it 'add
    nn to X' (nn in decimal)."""
    disassembly.comment_binary(p.get_start_loc(), "add {0} to X".format(p.get_memory("nn")), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_set_memory_r_loop(p, reg, other_reg):
    """Comment a loop that stores A in a run of bytes, counting 'reg' down
    to zero (BNE) or past it (BPL) and stepping 'other_reg' up as the index:
    e.g. 'Set 18 bytes of memory at l20e1+Y to 255', or 'Clear 18 bytes of
    memory at l20e1+Y' if A is 0.

    The count and A's value are what they are on entering the loop: from
    the CPU state after the last of the (up to three, optional) loads just
    before it, or, if none of those matched, py8dis's guess at the state at
    the loop's start (the 'optimistic' state, which, unlike the
    'pessimistic' one, isn't cleared at a label). They're only used if the
    loop's start has just one reference (the branch back to it). With BNE,
    a count of 0 sets 256 bytes; with BPL, a count of N sets N+1, or just
    one for a count of 129 or more. With an indirect store ('(zp),y'), the
    address isn't named. Nothing is commented if the branch doesn't go back
    to the loop's start."""

    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    comment_loc             = p.get_start_loc()
    is_stop_at_zero         = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL

    loop_addr               = p.get_binary_address('loop')

    # Find instruction just before 'loop': the last of the optional loads
    # that matched (one that didn't is an empty match, at the loop's start)
    load_addr               = p.get_binary_address('load3')
    if load_addr == loop_addr:
        load_addr           = p.get_binary_address('load2')
        if load_addr == loop_addr:
            load_addr       = p.get_binary_address('load1')
            if load_addr == loop_addr:
                load_addr   = None

    loop_has_one_reference  = p.num_references('loop') == 1
    if load_addr is None:
        state               = p.get_state('loop')
        # if we don't have any load instruction directly before the loop, use optimistic
        # state to guess the loop counter and value to store and hope for the best
        loop_counter        = state.optimistic[reg].value if state and state.optimistic[reg] and loop_has_one_reference else None
        to_value            = state.optimistic['a'].value if state and state.optimistic['a'] and loop_has_one_reference else None
    else:
        state               = p.get_state(load_addr)
        # we have at least one load instruction before the loop, use that to get the state
        loop_counter        = state.pessimistic[reg].value if state and state.pessimistic[reg] and loop_has_one_reference else None
        to_value            = state.pessimistic['a'].value if state and state.pessimistic['a'] and loop_has_one_reference else None
    is_store_indirect       = p.get_memory('zp')   # This is treated as a flag, being None if 'zp' isn't found
    dest_label              = ""
    to_value_string         = ""

    # How many bytes: the loop goes on while the counter isn't zero (BNE), or
    # isn't negative (BPL)
    bytes_to_set = None
    if loop_counter is not None:
        bytes_to_set = len(_loop_indices(loop_counter, -1, (lambda r: r != 0) if is_stop_at_zero else (lambda r: r < 0x80)))
    plus_reg = "+"+other_reg.upper()

    if to_value is not None:
        to_value_string = " to {0}".format(to_value)

    if is_store_indirect is None:
        dest_label = p.get_expr('addr', label_offset=0, final_offset=0)
        dest_label = utils.LazyString(" at %s%s", dest_label, plus_reg)

    if bytes_to_set is not None:
        bytes_to_set_string = " " + utils.count_with_units(bytes_to_set, "byte of memory", "bytes of memory")
    else:
        bytes_to_set_string = " {0} bytes of memory".format(reg.upper())

    # (The labels aren't named yet, so the text is a LazyString)
    if to_value == 0:
        # "This loop clears 18 bytes of memory at l20e1+Y"
        text = utils.LazyString("Clear%s%s", bytes_to_set_string, dest_label)
    else:
        # "This loop sets 18 bytes of memory at l20e1+Y to 0"
        text = utils.LazyString("Set%s%s%s", bytes_to_set_string, dest_label, to_value_string)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_set_memory_x_loop(p):
    """Post-trace function for a loop that counts X down and Y up, e.g.
    'sta addr,y : iny : dex : bne loop' (see comment_set_memory_r_loop())."""
    comment_set_memory_r_loop(p, 'x', 'y')

# ************************************************************************************************
def comment_set_memory_y_loop(p):
    """Post-trace function for a loop that counts Y down and X up, e.g.
    'sta addr,x : inx : dey : bne loop' (see comment_set_memory_r_loop())."""
    comment_set_memory_r_loop(p, 'y', 'x')


# ************************************************************************************************
# More opcodes, for the push and pull snippets
OPCODE_PHP                      = 0x08      # php
OPCODE_PHA                      = 0x48      # pha
OPCODE_PLP                      = 0x28      # plp
OPCODE_PLA                      = 0x68      # pla
OPCODE_TAX                      = 0xaa      # tax
OPCODE_TAY                      = 0xa8      # tay

def _comment_stack(p, names, verb):
    """Trace and comment a push or pull of the registers named (e.g.
    ['flags', 'A', 'X'], and verb 'push' or 'pull'), e.g. 'push flags,A,X
    onto the stack', if it's at least two of A, X and Y, each once;
    otherwise reject the match (see SnippetHelper.reject())."""
    registers = [name for name in names if name != "flags"]
    if len(registers) < 2 or len(set(registers)) != len(registers):
        p.reject()
    add_code_comment(p, "{0} {1} {2} the stack".format(verb, ",".join(names), "onto" if verb == "push" else "from"))

def comment_push(p):
    """Pre-trace function for code that pushes registers: trace it and
    comment it (see _comment_stack()). E.g. 'php : pha : txa : pha' pushes
    the flags, A, then X (each PHA pushes what was transferred to A just
    before it, if anything)."""
    memory = p.memory_binary
    start = p.match.start()
    names = []
    for addr in range(start, p.match.end()):
        if memory[addr] == OPCODE_PHP:
            names.append("flags")
        elif memory[addr] == OPCODE_PHA:
            previous = memory[addr - 1] if addr > start else None
            names.append({OPCODE_TXA: "X", OPCODE_TYA: "Y"}.get(previous, "A"))
    _comment_stack(p, names, "push")

def comment_pull(p):
    """Pre-trace function for code that pulls registers: trace it and
    comment it (see _comment_stack()). E.g. 'pla : tax : pla : plp' pulls
    X, then A, then the flags (each PLA pulls into what A is transferred to
    just after it, if anything). They're named in the order they were
    pushed: 'flags,A,X'."""
    memory = p.memory_binary
    end = p.match.end()
    names = []
    for addr in range(p.match.start(), end):
        if memory[addr] == OPCODE_PLP:
            names.append("flags")
        elif memory[addr] == OPCODE_PLA:
            following = memory[addr + 1] if addr + 1 < end else None
            names.append({OPCODE_TAX: "X", OPCODE_TAY: "Y"}.get(following, "A"))
    _comment_stack(p, list(reversed(names)), "pull")

# ************************************************************************************************
# ************************************************************************************************
# ************************************************************************************************
# The built in snippets

# Memory copy loops counting X or Y down to zero (BNE) or past it (BPL), e.g.
# 'ldx #7 : loop lda source,x : sta dest,x : dex : bpl loop'. Traced as code,
# and commented e.g. 'Copy 8 bytes of memory from source to dest' (see
# comment_memory_copy_loop()).
register_code_snippet(comment_memory_copy_loop, """
; memory copy, using X as the loop counter

comment
?   ldx #start_count
loop
load
    lda addr,x | lda (zp1,x)
store
    sta other,x | sta (zp2,x)
update
    dex
branch
    bpl loop | bne loop
""")

register_code_snippet(comment_memory_copy_loop, """
; memory copy, using Y as the loop counter

comment
?   ldy #start_count
loop
load
    lda addr,y | lda (zp1),y
store
    sta other,y | sta (zp2),y
update
    dey
branch
    bpl loop | bne loop
""")

# Memory copy loops counting X or Y down to a limit, e.g. 'ldy #9 : loop lda
# source,y : sta dest,y : dey : cpy #2 : bcs loop'. Traced as code, and
# commented as above (see comment_memory_copy_with_limited_end_loop()).
register_code_snippet(comment_memory_copy_with_limited_end_loop, """
; memory copy with final counter check, using Y as the loop counter

comment
?   ldy #start_count
loop
load
    lda addr,y | lda (zp1),y
store
    sta other,y | sta (zp2),y
update
    dey
    cpy #end_count
branch
    bcs loop
""")


register_code_snippet(comment_memory_copy_with_limited_end_loop, """
; memory copy with final counter check, using X as the loop counter

comment
?   ldx #start_count
loop
load
    lda addr,x | lda (zp1,x)
store
    sta other,x | sta (zp2,x)
update
    dex
    cpx #end_count
branch
    bcs loop
""")

# Memory copy loops counting X or Y up to a limit, e.g. 'ldx #0 : loop lda
# source,x : sta dest,x : inx : cpx #8 : bne loop'. Traced as code, and
# commented as above (see comment_memory_copy_increment()).
register_code_snippet(comment_memory_copy_increment, """
; memory copy increasing loop counter, using X as the loop counter
comment
?    ldx #start_count
loop
load
    lda addr,x | lda (zp1,x)
store
    sta other,x | sta (zp2,x)
update
    inx
    cpx #end_count
branch
    bne loop | bcc loop
""")

register_code_snippet(comment_memory_copy_increment, """
; memory copy increasing loop counter, using Y as the loop counter
comment
?    ldy #start_count
loop
load
    lda addr,y | lda (zp1),y
store
    sta other,y | sta (zp2),y
update
    iny
    cpy #end_count
branch
    bne loop | bcc loop
""")

# Pushing and pulling at least two of A, X and Y (and perhaps the flags), e.g.
# 'php : pha : txa : pha : tya : pha' ("push flags,A,X,Y onto the stack"), and
# the reverse, 'pla : tay : pla : tax : pla : plp'. Traced as code and
# commented before tracing (see comment_push() and comment_pull()).
register_snippet(comment_push, None, """
?   php
?   pha
    txa : pha | tya : pha
?   txa : pha | tya : pha
""")

register_snippet(comment_pull, None, """
    pla : tax | pla : tay
?   pla : tax | pla : tay
?   pla
?   plp
""")

# Adding a number to Y or X through A. Traced as code, and commented e.g.
# 'add 4 to Y' (see comment_add_to_y() and comment_add_to_x()).
register_code_snippet(comment_add_to_y, """
    tya
    clc
    adc #nn
    tay
""")

register_code_snippet(comment_add_to_x, """
    txa
    clc
    adc #nn
    tax
""")

# Loops that store A in a run of bytes, counting one index register down and
# stepping the other up, after up to three loads that set them up, e.g. 'lda
# #0 : ldy #0 : ldx #18 : loop sta table,y : iny : dex : bne loop'. Traced as
# code, and commented e.g. 'Clear 18 bytes of memory at table+Y' (see
# comment_set_memory_r_loop()). The loads' operands have names of their own
# (load_addr, zp_load), so that 'addr' and 'zp' are the store's.
register_code_snippet(comment_set_memory_x_loop, """
comment
load1
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
load2
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
load3
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
loop
    sta addr,y | sta (zp),y
    iny
    dex
branch
    bne loop | bpl loop
""")

register_code_snippet(comment_set_memory_y_loop, """
comment
load1
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
load2
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
load3
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda load_addr | lda load_addr,x | lda load_addr,y | lda zp_load | lda zp_load,x | lda zp_load,y | ldx zp_load | ldx load_addr | ldx zp_load,y | ldy zp_load | ldy zp_load,x | ldy load_addr | ldy load_addr,x
loop
    sta addr,x | sta (zp,x)
    inx
    dey
branch
    bne loop | bpl loop
""")

# Tables of the eight one-bit masks, $01 up to $80 or $80 down to $01. Not
# traced, but commented 'bitmask' inline at the start (before tracing).
register_comment_data_snippet("bitmask", """
    !byte 1
    !byte 2
    !byte 4
    !byte 8
    !byte $10
    !byte $20
    !byte $40
    !byte $80
""")

register_comment_data_snippet("bitmask", """
    !byte $80
    !byte $40
    !byte $20
    !byte $10
    !byte 8
    !byte 4
    !byte 2
    !byte 1
""")


# The snippets above are built in. Any registered from now on (e.g. by a
# control file, or acorn.py) belong to the current session.
_registering_builtins = False
