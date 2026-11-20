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
import config
import disassembly
import effectpattern
import movemanager
import snippet6502
import utils
import session
from align import Align
from binaryaddrtype import BinaryAddrType
from memorymanager import BinaryAddr
from maker import make_add
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
def _comment_loop(binary_loc, text):
    """Comment a loop (e.g. 'Copy 8 bytes of memory from source to dest'),
    on a line of its own before the label at binary_loc (where the loop, or
    the loads before it, start). The comment is indented, as the code is,
    if the code before it runs on into it (it isn't after an RTS or JMP,
    say, or data), so it reads as part of that code rather than as the
    start of a routine."""
    cpu = session.current().cpu
    indent = 0
    for length in (1, 2, 3):
        before = binary_loc.binary_addr - length
        if before < 0:
            break
        c = classification.get_classification(before)
        if isinstance(c, cpu.Opcode) and c.length() == length:
            state = cpu.cpu_states[before]
            if not c.is_block_end() and not (state is not None and state.always_branch):
                indent = 1
            break
    disassembly.comment_binary(binary_loc, text, indent=indent, align=Align.BEFORE_LABEL, auto_generated=True)

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
    _comment_loop(comment_loc, text)

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
    _comment_loop(comment_loc, text)


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
    _comment_loop(comment_loc, text)

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
    _comment_loop(comment_loc, text)

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
OPCODE_INY                      = 0xc8      # iny
OPCODE_DEY                      = 0x88      # dey
OPCODE_BPL                      = 0x10      # bpl loop

def _state_entering(p, label_name):
    """What's known for certain (a CpuStateDisposition) on coming into the
    instruction at the name's position from the instruction before it, or
    None if the code doesn't run on into it from there (e.g. the
    instruction before is data, or a JMP)."""
    cpu = session.current().cpu
    binary_addr = p.get_binary_address(label_name)
    for length in (1, 2, 3):
        before = binary_addr - length
        if before < 0:
            break
        c = classification.get_classification(before)
        if isinstance(c, cpu.Opcode) and c.length() == length:
            state = cpu.cpu_states[before]
            if c.is_block_end() or state is None or state.always_branch:
                return None
            return state.pessimistic
    return None

# (The register each update instruction steps, and by how much)
_UPDATES = {OPCODE_INX: ('x', 1), OPCODE_DEX: ('x', -1), OPCODE_INY: ('y', 1), OPCODE_DEY: ('y', -1)}
OPCODE_CPX_IMMEDIATE            = 0xe0      # cpx #nn
OPCODE_CPY_IMMEDIATE            = 0xc0      # cpy #nn

def _loop_registers(p, index_reg):
    """For a loop that indexes with 'index_reg' ('x' or 'y'), with its
    updates (one or two of INX, DEX, INY and DEY, at the name 'update'),
    its compare (perhaps none, at 'compare') and its branch back (at
    'branch'): (the index's step, the count register, its step, the branch
    opcode, whether there's a compare, the compare's value or None, a
    function that says whether the loop goes round again for the count's
    new value). The count is the index register itself if there's one
    update (e.g. 'inx : cpx #16 : bne loop'), or the other register if
    there are two (e.g. 'iny : dex : bne loop', counting X while indexing
    with Y). None if that isn't how it is, or if when the loop ends isn't
    known (a BCC without a compare)."""
    updates = [_UPDATES.get(p.memory_binary[addr]) for addr in range(p.get_binary_address('update'), p.get_binary_address('compare'))]
    if None in updates or len(updates) not in (1, 2):
        return None
    index_steps = [step for reg, step in updates if reg == index_reg]
    count = [(reg, step) for reg, step in updates if reg != index_reg]
    if len(index_steps) != 1 or len(count) > 1:
        return None
    count_reg, count_step = count[0] if count else (index_reg, index_steps[0])
    branch = p.get_memory('branch')
    has_compare = p.get_binary_address('compare') != p.get_binary_address('branch')
    if has_compare and p.get_memory('compare') != (OPCODE_CPX_IMMEDIATE if count_reg == 'x' else OPCODE_CPY_IMMEDIATE):
        # (Comparing the register that isn't the count)
        return None
    keep_going = _keep_going(p, branch, has_compare)
    if keep_going is None:
        return None
    limit = p.get_memory('compare', 1) if has_compare else None
    return index_steps[0], count_reg, count_step, branch, has_compare, limit, keep_going

def _loop_range(p, state, index_reg):
    """The bytes a loop that indexes with 'index_reg' works on (see
    _loop_registers()), from what's known entering it ('state'), as one of:

    ('known', the lowest index, the number of bytes), where the count's
    first value is known (and the index's, if it's another register);

    ('count', e.g. 'X' or 'X+1', the lowest index), where the count's first
    value isn't known, counting down to zero (BNE: X bytes, the index from
    1 to X if it's the count) or past it (BPL: X+1 bytes, from 0); if the
    index is another register, it must count up from a known value;

    ('up_to', the limit), where the index is the count, counting up from a
    value that isn't known to the compare's value (the last byte at
    limit-1);

    or None if it can't be said (e.g. the loop doesn't end, or the bytes
    aren't one run)."""
    loop = _loop_registers(p, index_reg)
    if loop is None:
        return None
    index_step, count_reg, count_step, branch, has_compare, limit, keep_going = loop
    count_start = state[count_reg].value
    count_text = count_reg.upper() if branch == OPCODE_BNE else count_reg.upper() + "+1"
    if count_reg == index_reg:
        if count_start is not None:
            run = _loop_run(count_start, count_step, keep_going)
            return None if run is None else ('known',) + run
        if count_step == 1 and has_compare and branch in (OPCODE_BNE, OPCODE_BCC) and limit > 0:
            return ('up_to', limit)
        if count_step == -1 and not has_compare:
            return ('count', count_text, 1 if branch == OPCODE_BNE else 0)
        return None
    index_start = state[index_reg].value
    if index_start is None:
        return None
    if count_start is not None:
        values = _loop_indices(count_start, count_step, keep_going)
        if values is None:
            return None
        n = len(values)
        lowest = index_start if index_step == 1 else index_start - (n - 1)
        if lowest < 0 or lowest + n - 1 > 0xff:
            # (The index wraps round)
            return None
        return ('known', lowest, n)
    if count_step == -1 and not has_compare and index_step == 1:
        return ('count', count_text, index_start)
    return None

def _keep_going(p, branch, has_compare):
    """For a loop's branch back ('branch', its opcode) after the update and
    perhaps a compare with an immediate value: a function that says whether
    it goes round again for the register's new value, or None if that isn't
    known (a BCC without a compare)."""
    limit = p.get_memory('compare', 1) if has_compare else None
    if has_compare:
        if branch == OPCODE_BNE:
            return lambda r: r != limit
        elif branch == OPCODE_BCC:
            return lambda r: r < limit
        else:
            # (BPL: while the difference is positive)
            return lambda r: ((r - limit) & 0xff) < 0x80
    elif branch == OPCODE_BNE:
        return lambda r: r != 0
    elif branch == OPCODE_BPL:
        return lambda r: r < 0x80
    # (BCC without a compare: the carry doesn't change in the loop)
    return None

def _is_traced(p, names):
    """Whether the instructions at the names' positions are traced code
    with CPU states (a post-trace function only comments code)."""
    cpu = session.current().cpu
    for name in names:
        binary_addr = p.get_binary_address(name)
        if not (isinstance(classification.get_classification(binary_addr), cpu.Opcode) and cpu.cpu_states[binary_addr] is not None):
            return False
    return True

def _matched(p, name):
    """Whether the name matched. (Only names in the snippet are asked for:
    asking for another would add it to the pattern's names.)"""
    return name in p.labels and p.get_memory(name) is not None

def _operand_modified(p, name, kind):
    """Whether the code changes the operand ('name', of a kind 'abs', 'zp' or
    'indirect') of a loop's instruction (self-modifying code: see
    Cpu6502.is_operand_modified()), so it isn't what it says."""
    return session.current().cpu.is_operand_modified(p.get_binary_address(name) - 1, 2 if kind == "abs" else 1)

def _pointed_to(p, state, name, offset):
    """For an indirect operand, the label of the byte 'offset' on from where
    the pointer points, if what's known entering the loop ('state') says
    where that is (see CpuStateDisposition.pointer()), otherwise None."""
    pointer = state.pointer(p.get_memory(name))
    if pointer is None:
        return None
    return disassembly.get_label((pointer + offset) & 0xffff, p.get_binary_address(name), binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)

def _first_byte(p, state, name, kind, lowest):
    """The first byte a loop's instruction uses, for its comment: the
    operand ('name', of a kind 'abs', 'zp' or 'indirect') plus 'lowest' (and
    an absolute operand is written as that byte's label minus 'lowest',
    unless the operand's address has a name of its own, when the first byte
    is e.g. 'buffer+1'; and an indirect one as the label of the byte it
    points to, if that's known). An absolute operand that the code changes
    (see _operand_modified()) is 'the address in' the label of the
    operand's bytes (e.g. 'the address in dest_low'). None if it can't be
    said: another operand that the code changes, or one that the code
    changes and isn't the first byte."""
    if _operand_modified(p, name, kind):
        if kind != "abs" or lowest:
            return None
        operand = p.get_binary_address(name)
        label = disassembly.get_label(movemanager.b2r(BinaryAddr(operand)), operand, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
        return utils.LazyString("the address in %s", label)
    if kind == "indirect":
        known = _pointed_to(p, state, name, lowest)
        if known is not None:
            return known
        return utils.LazyString("(%s)%s", p.get_expr(name), "+{0}".format(lowest) if lowest else "")
    if kind == "zp":
        zp_addr = p.get_memory(name)
        if lowest and zp_addr + lowest <= 0xff:
            # (Named by its own label, e.g. 'l00e2', rather than as 'l0000 + 226')
            return disassembly.get_label(zp_addr + lowest, p.get_binary_address(name), binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
        return make_add(p.get_expr(name), lowest) if lowest else p.get_expr(name)
    if lowest and _has_name(p.get_memory(name)):
        return make_add(p.get_expr(name), lowest)
    first = p.get_expr(name, label_offset=0, final_offset=lowest)
    if lowest:
        store_operand = p.get_binary_address(name)
        proposed_expression = p.make_subtract_wrapped(first, name, lowest)
        new_expression = classification.add_expression(store_operand, proposed_expression, force=False)
        if new_expression is not None and new_expression != proposed_expression:
            first = make_add(new_expression, lowest)
    return first

def _has_name(runtime_addr):
    """Whether the label at the runtime address (if any) has a name of its
    own (from label() and the like), rather than one py8dis makes up."""
    label = session.current().labels.labels.get(runtime_addr)
    return label is not None and any(label.explicit_names.values())

def _from_register_to(p, state, name, kind, register, limit, with_from=True):
    """For a loop counting up from the register's value (not known) to
    'limit', the bytes the operand ('name', of a kind 'abs', 'zp' or
    'indirect') covers, e.g. 'from table+X to table + 63' (without 'from'
    if not 'with_from'), or None if the code changes the operand (see
    _operand_modified())."""
    if _operand_modified(p, name, kind):
        return None
    if kind == "indirect":
        first, last = _pointed_to(p, state, name, 0), _pointed_to(p, state, name, limit - 1)
        if first is None:
            first, last = utils.LazyString("(%s)", p.get_expr(name)), utils.LazyString("(%s)+%d", p.get_expr(name), limit - 1)
    else:
        # (The last byte as e.g. 'table + 63', rather than a new label in
        # the middle of the table)
        first, last = p.get_expr(name), make_add(p.get_expr(name), limit - 1)
    return utils.LazyString("%s%s+%s to %s", "from " if with_from else "", first, register, last)

def comment_set_memory_one_register_loop(p, reg, zero=False):
    """Comment a loop that stores A (or with 'zero', zero: the 65C02's STZ)
    in one or more runs of bytes (up to four stores each time round), with
    one register ('reg') as both the index and the count, e.g. 'sta table,y
    : iny : cpy #16 : bne loop' or 'sta table,x : sta table+256,x : dex :
    bne loop': e.g. 'Clear 16 bytes of memory from table onwards', 'Clear
    512 bytes of memory from table onwards' (runs that join up are given as
    one), or 'Set 8 bytes of memory from table+1 onwards to 255'. The
    comment goes before the loop's label.

    The register's first value and A's value are what's known for certain
    on coming into the loop from the instruction before it (see
    join_states_at_labels(), which knows what's known across labels), and
    the loop's start must have just one reference (the branch back to it),
    so that it's the only way in. The bytes are worked out by stepping the
    register through the loop (see _loop_run()). If the register's first
    value isn't known, the loop is described in terms of it where the end
    is known: counting up to a limit ('Set memory from table+X to table+63
    to 32', taking X to be below the limit), or counting down to zero
    ('Set X bytes of memory from table+1 onwards') or past it ('Set X+1
    bytes of memory from table onwards', taking X to be below $80). Nothing
    is commented if the loop doesn't end, if the bytes aren't one run, or if
    the branch doesn't go back to the loop's start. The first byte is named
    by its label, and if it isn't the operand's address, the operand is
    written as that label minus the difference. With an indirect store
    ('(ptr),y'), the first byte is given as the label of where the pointer
    points, if what's known coming into the loop says (e.g. after 'lda
    #<buf : sta ptr : lda #>buf : sta ptr+1', whose loads are then written
    that way: see Cpu6502.name_pointer_loads()), otherwise as e.g.
    '(ptr)+2'."""
    cpu = session.current().cpu
    if not _is_traced(p, ('loop', 'update', 'branch')):
        return
    if not p.check_branch_matches('loop') or p.num_references('loop') != 1:
        return
    state = _state_entering(p, 'loop')
    if state is None:
        return
    to_value = 0 if zero else state['a'].value
    rng = _loop_range(p, state, reg)
    if rng is None:
        return

    # The stores, each as (the name of its operand, and the kind: 'abs',
    # 'zp' or 'indirect')
    stores = []
    for n in range(1, 5):
        for name, kind in (("addr%d" % n, "abs"), ("zpaddr%d" % n, "zp"), ("zpptr%d" % n, "indirect")):
            if _matched(p, name):
                stores.append((name, kind))
    if not stores:
        return
    if zero:
        # (Only the 65C02's STZ: the same opcodes are other instructions on
        # the 6510)
        for name, _ in stores:
            c = classification.get_classification(p.get_binary_address(name) - 1)
            if not (isinstance(c, cpu.Opcode) and c.mnemonic.upper() == "STZ"):
                return

    if to_value == 0:
        verb, to_text = "Clear", ""
    else:
        verb, to_text = "Set", "" if to_value is None else " to {0}".format(to_value)
    register = reg.upper()

    if rng[0] == 'known':
        _, lowest, count = rng
        # Each store's bytes, as (first address, count, store), with those
        # that join up (absolute stores, one after another) made one
        runs = []
        for name, kind in stores:
            address = p.get_memory(name) + lowest if kind == "abs" else None
            if runs and address is not None and runs[-1][0] is not None and runs[-1][0] + runs[-1][1] == address:
                runs[-1] = (runs[-1][0], runs[-1][1] + count, runs[-1][2])
            else:
                runs.append((address, count, (name, kind)))
        parts = []
        for i, (address, n, (name, kind)) in enumerate(runs):
            units = ("byte of memory", "bytes of memory") if i == 0 else ("byte", "bytes")
            first = _first_byte(p, state, name, kind, lowest)
            if first is None:
                return
            parts.append(utils.LazyString("%s from %s onwards", utils.count_with_units(n, *units), first))
    elif rng[0] == 'up_to':
        # Counting up to the limit, from the register's value: the last
        # byte is at limit-1
        parts = [_from_register_to(p, state, name, kind, register, rng[1]) for name, kind in stores]
        if None in parts:
            return
        parts[0] = utils.LazyString("memory %s", parts[0])
    else:
        # Counting down to zero (the register's value down to 1) or past it
        # (down to 0)
        _, count, lowest = rng
        parts = []
        for i, (name, kind) in enumerate(stores):
            units = "bytes of memory" if i == 0 else "bytes"
            first = _first_byte(p, state, name, kind, lowest)
            if first is None:
                return
            parts.append(utils.LazyString("%s %s from %s onwards", count, units, first))

    # e.g. "Clear 256 bytes of memory from table onwards, and 256 bytes from
    # table+512 onwards"
    text = utils.LazyString("%s %s%s", verb, utils.LazyString(", and ".join(["%s"] * len(parts)), *parts), to_text)
    _comment_loop(p.get_start_loc(), text)
    # (And the loads that set a pointer whose value is known, before the
    # loop, as its label's low and high bytes, e.g. 'lda #<buffer')
    for name, kind in stores:
        if kind == "indirect":
            pointer = state.pointer(p.get_memory(name))
            if pointer is not None:
                cpu.name_pointer_loads(p.get_binary_address('loop'), p.get_memory(name), pointer)

def comment_set_memory_y_index_loop(p):
    """Post-trace function for a loop that stores A with Y as both the
    index and the count (see comment_set_memory_one_register_loop())."""
    comment_set_memory_one_register_loop(p, 'y')

def comment_set_memory_x_index_loop(p):
    """Post-trace function for a loop that stores A with X as both the
    index and the count (see comment_set_memory_one_register_loop())."""
    comment_set_memory_one_register_loop(p, 'x')

OPCODE_BEQ                      = 0xf0      # beq found
# (LDA with an operand, for comment_search_loop())
OPCODES_LDA                     = {0xbd, 0xb5, 0xb9, 0xb1}

def _operand(p, n):
    """The n'th operand of a loop's instructions (its name 'addr<n>',
    'zpaddr<n>' or 'zpptr<n>'), as (the name, the kind: 'abs', 'zp' or
    'indirect'), or None if none of them matched."""
    for name, kind in (("addr%d" % n, "abs"), ("zpaddr%d" % n, "zp"), ("zpptr%d" % n, "indirect")):
        if _matched(p, name):
            return name, kind
    return None

def _bytes_from(p, state, rng, name, kind, index_reg):
    """The bytes an operand ('name', of a kind 'abs', 'zp' or 'indirect')
    covers over a loop (whose range 'rng' is from _loop_range()), e.g. '16
    bytes from table', 'X+1 bytes from table' or 'from table+X to table +
    7', or None if it can't be said (see _first_byte())."""
    if rng[0] == 'up_to':
        return _from_register_to(p, state, name, kind, index_reg.upper(), rng[1])
    if rng[0] == 'known':
        _, lowest, count = rng
        count_text = utils.count_with_units(count, "byte", "bytes")
    else:
        _, count, lowest = rng
        count_text = count + " bytes"
    first = _first_byte(p, state, name, kind, lowest)
    return None if first is None else utils.LazyString("%s from %s", count_text, first)

def _name_pointer_loads(p, state, operands):
    """For each indirect operand of a loop (as (name, kind)) whose pointer
    is known entering it ('state'), write the immediate loads that set the
    pointer before the loop as its label's low and high bytes (see
    Cpu6502.name_pointer_loads())."""
    for name, kind in operands:
        if kind == "indirect":
            pointer = state.pointer(p.get_memory(name))
            if pointer is not None:
                session.current().cpu.name_pointer_loads(p.get_binary_address('loop'), p.get_memory(name), pointer)

def _loop_start(p, names):
    """What's known for certain entering a loop (see _state_entering()), if
    its instructions at the names are traced, its branch goes back to its
    start, and that start has just one reference (the branch back), so
    that it's the only way in; otherwise None."""
    if not _is_traced(p, names):
        return None
    if not p.check_branch_matches('loop') or p.num_references('loop') != 1:
        return None
    return _state_entering(p, 'loop')

def comment_search_loop(p, reg):
    """Comment a loop that looks through a run of bytes for one, indexing
    with one register ('reg'), e.g. 'cmp table,x : beq found : inx : cpx #16
    : bne loop' ('Search 16 bytes from table for A'), 'lda (ptr),y : beq
    found : iny : bne loop' ('Search 256 bytes from (ptr) for 0'), 'lda
    table,x : cmp #13 : bne found : dex : bpl loop' ('Search 8 bytes from
    table for a byte other than 13'), or 'cmp table,y : beq found : iny :
    dex : bne loop' (counting with X, see _loop_registers()). What's
    searched for is A (or its value, if it's known entering the loop), 0
    (LDA), or the CMP's value; with BNE rather than BEQ, it's a byte other
    than that. The comment goes before the loop's label.

    The bytes are worked out as for comment_set_memory_one_register_loop()
    (which see), from the registers' first values, or, if the count's isn't
    known, in terms of it: e.g. 'Search X+1 bytes from table for A' for
    'dex : bpl loop' (see _loop_range())."""
    state = _loop_start(p, ('loop', 'found_branch', 'update', 'branch'))
    if state is None:
        return
    operand = _operand(p, 1)
    rng = _loop_range(p, state, reg)
    if operand is None or rng is None:
        return
    name, kind = operand

    # What it looks for
    hex = config.get_assembler().hex
    def number(v):
        return hex(v) if v > 9 else str(v)
    if _matched(p, 'value'):
        target = number(p.get_memory('value'))
    elif p.memory_binary[p.get_binary_address('loop')] in OPCODES_LDA:
        target = "0"
    else:
        a = state['a'].value
        target = "A" if a is None else number(a)
    if p.get_memory('found_branch') != OPCODE_BEQ:
        target = "a non-zero byte" if target == "0" else "a byte other than " + target

    where = _bytes_from(p, state, rng, name, kind, reg)
    if where is None:
        return
    _comment_loop(p.get_start_loc(), utils.LazyString("Search %s for %s", where, target))
    _name_pointer_loads(p, state, [operand])

def comment_compare_loop(p, reg):
    """Comment a loop that compares two runs of bytes, indexing both with
    one register ('reg') and leaving the loop at the first difference: 'lda
    a,x : cmp b,x : bne differ' (or 'eor b,x'), then the update, perhaps a
    compare, and the branch back, as for comment_search_loop(); e.g. 'ldx #4
    : loop lda a,x : eor b,x : bne differ : dex : bne loop' ('Compare 4
    bytes from a+1 with b+1'), or 'ldy #0 : loop lda (ptr),y : cmp buffer,y
    : bne differ : iny : dex : bne loop' ('Compare X bytes from (ptr) with
    buffer'). The comment goes before the loop's label."""
    state = _loop_start(p, ('loop', 'found_branch', 'update', 'branch'))
    if state is None:
        return
    first, second = _operand(p, 1), _operand(p, 2)
    rng = _loop_range(p, state, reg)
    if first is None or second is None or rng is None:
        return
    where = _bytes_from(p, state, rng, *first, reg)
    if rng[0] == 'up_to':
        other = _from_register_to(p, state, *second, reg.upper(), rng[1], with_from=False)
    else:
        other = _first_byte(p, state, *second, rng[2] if rng[0] == 'count' else rng[1])
    if where is None or other is None:
        return
    _comment_loop(p.get_start_loc(), utils.LazyString("Compare %s with %s", where, other))
    _name_pointer_loads(p, state, [first, second])

# (The index register of each first instruction of a compare loop with two
# index registers: LDA abs,X, zp,X, abs,Y and (zp),Y)
_LDA_INDEX = {0xbd: 'x', 0xb5: 'x', 0xb9: 'y', 0xb1: 'y'}

def _from_register(p, name, kind, register, offset):
    """An operand ('name', of a kind 'abs', 'zp' or 'indirect') plus a
    register whose value isn't known, plus 'offset' (0 or less), e.g.
    'table+Y', '(ptr)+Y' or 'table+Y-6', or None if the code changes the
    operand (see _operand_modified())."""
    if _operand_modified(p, name, kind):
        return None
    base = utils.LazyString("(%s)", p.get_expr(name)) if kind == "indirect" else p.get_expr(name)
    return utils.LazyString("%s+%s%s", base, register.upper(), "" if offset == 0 else "%d" % offset)

def comment_compare_two_register_loop(p):
    """Comment a loop that compares two runs of bytes, indexing each with a
    different register and stepping both, and leaving the loop at the
    first difference: e.g. 'ldx #6 : loop lda a,y : cmp b,x : bne differ :
    dey : dex : bpl loop' ('Compare 7 bytes from a+Y-6 with b'). The count
    is the register the branch back tests (or that's compared, if there's
    a compare), whose first value must be known (see _loop_run()); it must
    count down, or up to a compare (not round to zero from somewhere else,
    which is more likely a compare that runs until the bytes differ, e.g.
    a match against a table of names). The other register's runs are given
    from its first value if that's known, otherwise in terms of it, e.g.
    'a+Y'. If one register counts up and the other down, the second run
    is compared in reverse ('Compare 4 bytes from a+Y with b, in reverse').
    The comment goes before the loop's label."""
    state = _loop_start(p, ('loop', 'found_branch', 'update', 'branch'))
    if state is None:
        return
    first, second = _operand(p, 1), _operand(p, 2)
    if first is None or second is None:
        return
    reg1 = _LDA_INDEX.get(p.memory_binary[p.get_binary_address('loop')])
    reg2 = 'y' if reg1 == 'x' else 'x'
    updates = [_UPDATES.get(p.memory_binary[addr]) for addr in range(p.get_binary_address('update'), p.get_binary_address('compare'))]
    if reg1 is None or None in updates or sorted(reg for reg, _ in updates) != ['x', 'y']:
        return
    steps = dict(updates)
    branch = p.get_memory('branch')
    has_compare = p.get_binary_address('compare') != p.get_binary_address('branch')
    if has_compare:
        count_reg = 'x' if p.get_memory('compare') == OPCODE_CPX_IMMEDIATE else 'y'
    else:
        # (The update just before the branch sets the flags it tests)
        count_reg = updates[-1][0]
    if steps[count_reg] == 1 and not has_compare:
        return
    keep_going = _keep_going(p, branch, has_compare)
    count_start = state[count_reg].value
    if keep_going is None or count_start is None:
        return
    run = _loop_run(count_start, steps[count_reg], keep_going)
    if run is None:
        return
    count_lowest, n = run

    # Each operand's first byte (its lowest), from the register that
    # indexes it
    other_reg = 'y' if count_reg == 'x' else 'x'
    other_start = state[other_reg].value
    other_step = steps[other_reg]
    def lowest_byte(name, kind, reg):
        if reg == count_reg:
            return _first_byte(p, state, name, kind, count_lowest)
        if other_start is None:
            return _from_register(p, name, kind, reg, 0 if other_step == 1 else -(n - 1))
        lowest = other_start if other_step == 1 else other_start - (n - 1)
        if lowest < 0 or lowest + n - 1 > 0xff:
            return None
        return _first_byte(p, state, name, kind, lowest)
    first_text = lowest_byte(*first, reg1)
    second_text = lowest_byte(*second, reg2)
    if first_text is None or second_text is None:
        return
    reverse = "" if steps['x'] == steps['y'] else ", in reverse"
    _comment_loop(p.get_start_loc(), utils.LazyString("Compare %s from %s with %s%s", utils.count_with_units(n, "byte", "bytes"), first_text, second_text, reverse))
    _name_pointer_loads(p, state, [first, second])

def comment_search_x_index_loop(p):
    """Post-trace function for a loop that looks through bytes, indexing
    them with X (see comment_search_loop())."""
    comment_search_loop(p, 'x')

def comment_search_y_index_loop(p):
    """Post-trace function for a loop that looks through bytes, indexing
    them with Y (see comment_search_loop())."""
    comment_search_loop(p, 'y')

def comment_compare_x_index_loop(p):
    """Post-trace function for a loop that compares two runs of bytes,
    indexing them with X (see comment_compare_loop())."""
    comment_compare_loop(p, 'x')

def comment_compare_y_index_loop(p):
    """Post-trace function for a loop that compares two runs of bytes,
    indexing them with Y (see comment_compare_loop())."""
    comment_compare_loop(p, 'y')

def comment_clear_memory_x_index_loop(p):
    """Post-trace function for a loop that stores zero (the 65C02's STZ)
    with X as both the index and the count (see
    comment_set_memory_one_register_loop())."""
    comment_set_memory_one_register_loop(p, 'x', zero=True)


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

# (These two only comment code that's traced: their matches aren't traced
# as code, since their bytes are common in data)
register_snippet(None, comment_set_memory_y_index_loop, """
loop
    sta addr1,y | sta (zpptr1),y
?   sta addr2,y | sta (zpptr2),y
?   sta addr3,y | sta (zpptr3),y
?   sta addr4,y | sta (zpptr4),y
update
    iny | dey
compare
?   cpy #nn
branch
    bne loop | bpl loop | bcc loop
""")

register_snippet(None, comment_set_memory_x_index_loop, """
loop
    sta addr1,x | sta zpaddr1,x
?   sta addr2,x | sta zpaddr2,x
?   sta addr3,x | sta zpaddr3,x
?   sta addr4,x | sta zpaddr4,x
update
    inx | dex
compare
?   cpx #nn
branch
    bne loop | bpl loop | bcc loop
""")

# The 65C02's STZ in such a loop, which clears the bytes, e.g. 'ldx #15 :
# loop stz table,x : dex : bpl loop' ('Clear 16 bytes of memory from table
# onwards'). (Not traced, as above: only the 65C02's code has STZ.)
register_snippet(None, comment_clear_memory_x_index_loop, """
loop
    stz addr1,x | stz zpaddr1,x
?   stz addr2,x | stz zpaddr2,x
?   stz addr3,x | stz zpaddr3,x
?   stz addr4,x | stz zpaddr4,x
update
    inx | dex
compare
?   cpx #nn
branch
    bne loop | bpl loop | bcc loop
""")

# Loops that compare two runs of bytes, indexing both with one register (and
# counting with it or with the other), and leaving the loop at the first
# difference ('lda a,x : cmp b,x : bne differ', or 'eor b,x'). Commented e.g.
# 'Compare 4 bytes from a with b' (see comment_compare_loop()). (Not traced,
# as above. Before the searches, since a match is skipped if it overlaps an
# earlier one, and a search would match from the CMP.)
register_snippet(None, comment_compare_x_index_loop, """
loop
    lda addr1,x : cmp addr2,x | lda addr1,x : cmp zpaddr2,x | lda zpaddr1,x : cmp addr2,x | lda zpaddr1,x : cmp zpaddr2,x | lda addr1,x : eor addr2,x | lda addr1,x : eor zpaddr2,x | lda zpaddr1,x : eor addr2,x | lda zpaddr1,x : eor zpaddr2,x
found_branch
    bne differ
update
    inx | dex | inx : dey | dex : dey | dey : inx | dey : dex
compare
?   cpx #nn | cpy #nn
branch
    bne loop | bpl loop | bcc loop
""")

register_snippet(None, comment_compare_y_index_loop, """
loop
    lda addr1,y : cmp addr2,y | lda addr1,y : cmp (zpptr2),y | lda (zpptr1),y : cmp addr2,y | lda (zpptr1),y : cmp (zpptr2),y | lda addr1,y : eor addr2,y | lda addr1,y : eor (zpptr2),y | lda (zpptr1),y : eor addr2,y | lda (zpptr1),y : eor (zpptr2),y
found_branch
    bne differ
update
    iny | dey | iny : dex | dey : dex | dex : iny | dex : dey
compare
?   cpy #nn | cpx #nn
branch
    bne loop | bpl loop | bcc loop
""")

# Loops that compare two runs of bytes indexed by different registers,
# stepping both ('lda a,y : cmp b,x : bne differ : dey : dex : bpl loop').
# Commented e.g. 'Compare 7 bytes from a+Y-6 with b' (see
# comment_compare_two_register_loop()). (Not traced, as above.)
register_snippet(None, comment_compare_two_register_loop, """
loop
    lda addr1,y : cmp addr2,x | lda addr1,y : cmp zpaddr2,x | lda (zpptr1),y : cmp addr2,x | lda (zpptr1),y : cmp zpaddr2,x | lda addr1,x : cmp addr2,y | lda zpaddr1,x : cmp addr2,y | lda addr1,x : cmp (zpptr2),y | lda zpaddr1,x : cmp (zpptr2),y | lda addr1,y : eor addr2,x | lda addr1,y : eor zpaddr2,x | lda (zpptr1),y : eor addr2,x | lda (zpptr1),y : eor zpaddr2,x | lda addr1,x : eor addr2,y | lda zpaddr1,x : eor addr2,y | lda addr1,x : eor (zpptr2),y | lda zpaddr1,x : eor (zpptr2),y
found_branch
    bne differ
update
    inx : iny | inx : dey | dex : iny | dex : dey | iny : inx | iny : dex | dey : inx | dey : dex
compare
?   cpx #nn | cpy #nn
branch
    bne loop | bpl loop | bcc loop
""")

# Loops that look through bytes for one, indexing with one register and
# counting with it or with the other: comparing A with each byte ('cmp
# table,x'), loading each to look for 0 ('lda table,x'), or loading each and
# comparing it with a value ('lda table,x : cmp #13'), and leaving the loop
# when it's found (BEQ), or when a byte other than that is found (BNE).
# Commented e.g. 'Search 16 bytes from table for A' (see
# comment_search_loop()). (Not traced, as above.)
register_snippet(None, comment_search_x_index_loop, """
loop
    lda addr1,x : cmp #value | lda zpaddr1,x : cmp #value | cmp addr1,x | cmp zpaddr1,x | lda addr1,x | lda zpaddr1,x
found_branch
    beq found | bne found
update
    inx | dex | inx : dey | dex : dey | dey : inx | dey : dex
compare
?   cpx #nn | cpy #nn
branch
    bne loop | bpl loop | bcc loop
""")

register_snippet(None, comment_search_y_index_loop, """
loop
    lda addr1,y : cmp #value | lda (zpptr1),y : cmp #value | cmp addr1,y | cmp (zpptr1),y | lda addr1,y | lda (zpptr1),y
found_branch
    beq found | bne found
update
    iny | dey | iny : dex | dey : dex | dex : iny | dex : dey
compare
?   cpy #nn | cpx #nn
branch
    bne loop | bpl loop | bcc loop
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
