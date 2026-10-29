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

# Opcodes
OPCODE_LDA_ZP_COMMA_X           = 0xb5      # lda zp,x
OPCODE_STA_ZP_COMMA_X           = 0x95      # sta zp,x
OPCODE_DEX                      = 0xca      # dex
OPCODE_INX                      = 0xe8      # inx
OPCODE_BNE                      = 0xd0      # bne loop
OPCODE_TXA                      = 0x8a      # txa
OPCODE_TYA                      = 0x98      # tya

# Snippets are 'SnippetDetails' which contain a regex for binary data to find common code tropes,
# and two associated functions (for commenting, adding expressions etc).
# One function is executed before the code is traced (or rather, once the code has been traced from the
# entry points given, so that a match in the middle of an instruction can be ignored: see
# snippethelper.SnippetRejected), allowing new entry points to be added for the trace.
# The other happens after tracing which allows for more detailed comments to be added because we know the
# cpu_state of registers.
#
# The snippets in use are the session's 'snippets' list (see session.py), which
# starts as a copy of the built in snippets below. The register_*() functions
# add to it.
BUILTIN_SNIPPETS = []

# True while this module is registering the built in snippets, when it's first
# imported
_registering_builtins = True

def _add(details):
    if _registering_builtins:
        BUILTIN_SNIPPETS.append(details)
    else:
        session.current().snippets.append(details)

# ************************************************************************************************
def add_entry(p):
    p.entry()

def add_code_comment(p, comment):
    p.entry()
    disassembly.comment_binary(p.get_start_loc(), comment, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

def add_data_comment(p, comment):
    disassembly.comment_binary(p.get_start_loc(), comment, align=Align.INLINE, auto_generated=True)


def parse_snippet(snippet):
    """A regex snippet (snippet6502.Snippet) or, if it describes effects, an
    effect pattern (effectpattern.EffectPattern)."""
    if effectpattern.is_effect_pattern(snippet):
        return effectpattern.EffectPattern(snippet)
    return snippet6502.parse_snippet(snippet)

def register_snippet(pre_trace_fn, post_trace_fn, snippet):
    """Register a snippet: a regex snippet (see snippet6502.parse_snippet())
    or an effect pattern (see effectpattern.py), with the functions to call
    for each match, before and after tracing (or None). For an effect
    pattern, the pre-trace function is called once for each match found
    while tracing (it can add entry points and labels), and the post-trace
    function once for each match in the code as finally traced, after the
    code has been analysed (for comments and expressions)."""
    _add(SnippetDetails(pre_trace_fn, None, post_trace_fn, None, parse_snippet(snippet)))

def register_code_snippet(post_trace_fn, snippet):
    _add(SnippetDetails(add_entry, None, post_trace_fn, None, parse_snippet(snippet)))

def register_data_snippet(post_trace_fn, snippet):
    _add(SnippetDetails(None, None, post_trace_fn, None, parse_snippet(snippet)))

def register_comment_code_snippet(comment, snippet):
    _add(SnippetDetails(add_code_comment, comment, None, None, parse_snippet(snippet)))

def register_comment_data_snippet(comment, snippet):
    _add(SnippetDetails(add_data_comment, comment, None, None, parse_snippet(snippet)))

# ************************************************************************************************
def comment_memory_copy_loop(p):
    # e.g. "This loop copies 8 bytes from source to dest"

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

    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = p.make_subtract_wrapped(source_label, 'addr', offset)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                source_label = make_add(new_expression, 1)
        source_label = utils.LazyString(" from %s", source_label)
        #if bytes_to_copy is None:
        #    source_label = utils.LazyString("%s+%s", source_label, reg.upper())

    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=offset)

        if offset:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = p.make_subtract_wrapped(dest_label, 'other', offset)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                dest_label = make_add(new_expression, 1)
        dest_label = utils.LazyString(" to %s", dest_label)
        #if bytes_to_copy is None:
        #    dest_label = utils.LazyString("%s+%s", dest_label, reg.upper())

    offset_string = ""

    if bytes_to_copy is not None:
        if not is_stop_at_zero:
            # "bpl loop"
            if bytes_to_copy > 128:
                # "bpl loop" and initial value is 129 or higher then the loop will only happen once.
                # This is for completeness/correctness only - why you would write a loop like this?
                bytes_to_copy = 1
            else:
                # Stop when reg becomes 255
                bytes_to_copy += 1

        # with a loop counter initialised to zero, we actually loop 256 times
        if is_stop_at_zero and (bytes_to_copy == 0):
            # "bne loop"
            bytes_to_copy = 256
    else:
        if not is_stop_at_zero:
            offset_string = "+1"

    if bytes_to_copy is not None:
        bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
    else:
        bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_memory_copy_with_limited_end_loop(p):
    # e.g. "This loop copies 8 bytes from source to dest"

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

    # The loop counts down from start_count to end_count inclusive, wrapping
    # round from 0 to 255 if start_count is lower than end_count. (A
    # start_count of zero is valid.)
    if start_count is not None:
        bytes_to_copy = ((start_count - end_count) & 0xff) + 1
    else:
        bytes_to_copy = None

    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=end_count)

        if end_count:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = p.make_subtract_wrapped(source_label,'addr',end_count)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                source_label = make_add(new_expression, 1)
        source_label = utils.LazyString(" from %s", source_label)
        #if bytes_to_copy is None:
        #    source_label = utils.LazyString("%s+%s", source_label, reg.upper())

    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=end_count)

        if end_count:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = p.make_subtract_wrapped(dest_label, 'other', end_count)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression is not None and new_expression != proposed_expression:
                dest_label = make_add(new_expression, 1)
        dest_label = utils.LazyString(" to %s", dest_label)
        #if bytes_to_copy is None:
        #    dest_label = utils.LazyString("%s+%s", dest_label, reg.upper())

    # If start_count isn't known, the number of bytes is the initial value of
    # the register minus (end_count - 1)
    offset_string = "" if end_count == 1 else "-%d" % (end_count - 1)

    if bytes_to_copy is not None:
        bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
    else:
        bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)


# ************************************************************************************************
def comment_memory_copy_increment(p):
    # e.g. "This loop copies 8 bytes from source to dest"

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
    state               = p.get_state('comment')
    start_count         = state.pessimistic[reg].value if state and state.pessimistic[reg] else None
    if start_count is None:
        start_count = p.get_memory("start_count")
        if start_count is None:
            return

    bytes_to_copy = end_count - start_count

    if is_load_indirect is None:
        source_label = p.get_expr('addr', label_offset=0, final_offset=start_count)

        source_binary_addr = p.get_binary_address('load')+1
        proposed_expression = p.make_subtract_wrapped(source_label, 'addr', start_count)
        new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
        if new_expression is not None and new_expression != proposed_expression:
            source_label = p.make_subtract_wrapped(new_expression, 'addr', start_count)
        source_label = utils.LazyString(" from %s", source_label)

    if is_store_indirect is None:
        dest_label = p.get_expr('other', label_offset=0, final_offset=start_count)

        dest_binary_addr = p.get_binary_address('store')+1
        proposed_expression = p.make_subtract_wrapped(dest_label, 'other', start_count)
        new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
        if new_expression is not None and new_expression != proposed_expression:
            dest_label = p.make_subtract_wrapped(new_expression, 'other', start_count)
        dest_label = utils.LazyString(" to %s", dest_label)

    if bytes_to_copy is not None:
        bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
    else:
        bytes_to_copy_string = " some bytes of memory"

    # (The labels aren't named yet, so the text is a LazyString)
    text = utils.LazyString("Copy%s%s%s", bytes_to_copy_string, source_label, dest_label)
    disassembly.comment_binary(comment_loc, text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_add_to_y(p):
    disassembly.comment_binary(p.get_start_loc(), "add {0} to Y".format(p.get_memory("nn")), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_add_to_x(p):
    disassembly.comment_binary(p.get_start_loc(), "add {0} to X".format(p.get_memory("nn")), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_set_memory_r_loop(p, reg, other_reg):
    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    comment_loc             = p.get_start_loc()
    is_stop_at_zero         = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL

    loop_addr               = p.get_binary_address('loop')

    # Find instruction just before 'loop'
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

    bytes_to_set = loop_counter
    plus_reg = "+"+other_reg.upper()
    if bytes_to_set is not None:
        if not is_stop_at_zero:
            bytes_to_set += 1

    if to_value is not None:
        to_value_string = " to {0}".format(to_value)

    if is_store_indirect is None:
        dest_label = p.get_expr('addr', label_offset=0, final_offset=0)
        dest_label = utils.LazyString(" at %s%s", dest_label, plus_reg)

    if bytes_to_set is not None:
        bytes_to_set_string = " " + utils.count_with_units(bytes_to_set, "byte", "bytes"+ " of memory")
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
    comment_set_memory_r_loop(p, 'x', 'y')

# ************************************************************************************************
def comment_set_memory_y_loop(p):
    comment_set_memory_r_loop(p, 'y', 'x')


# ************************************************************************************************
OPCODE_PHP                      = 0x08      # php
OPCODE_PHA                      = 0x48      # pha
OPCODE_PLP                      = 0x28      # plp
OPCODE_PLA                      = 0x68      # pla
OPCODE_TAX                      = 0xaa      # tax
OPCODE_TAY                      = 0xa8      # tay

def _comment_stack(p, names, verb):
    """Comment a push or pull of the registers named (e.g. ['flags', 'A',
    'X']), if it's at least two of A, X and Y, each once; otherwise ignore the
    match."""
    registers = [name for name in names if name != "flags"]
    if len(registers) < 2 or len(set(registers)) != len(registers):
        p.reject()
    add_code_comment(p, "{0} {1} {2} the stack".format(verb, ",".join(names), "onto" if verb == "push" else "from"))

def comment_push(p):
    """e.g. 'php : pha : txa : pha' pushes the flags, A, then X (each PHA
    pushes what was transferred to A just before it, if anything)"""
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
    """e.g. 'pla : tax : pla : plp' pulls X, then A, then the flags. They're
    named in the order they were pushed: 'flags,A,X'."""
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
; memory copy increasing loop counter, using X as the loop counter
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
# the reverse, 'pla : tay : pla : tax : pla : plp'
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

register_code_snippet(comment_set_memory_x_loop, """
comment
load1
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
load2
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
load3
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
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
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
load2
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
load3
?   lda #nn1 | ldx #nn2 | ldy #nn3 | lda addr | lda addr,x | lda addr,y | lda zp | lda zp,x | lda zp,y | ldx zp | ldx addr | ldx zp,y | ldy zp | ldy zp,x | ldy addr | ldy addr,x
loop
    sta addr,x | sta (zp,x)
    inx
    dey
branch
    bne loop | bpl loop
""")

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
