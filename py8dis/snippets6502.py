import classification
import disassembly
import snippet6502
import utils
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from snippethelper import *

# Opcodes
OPCODE_LDA_ZP_COMMA_X           = 0xb5      # lda zp,x
OPCODE_STA_ZP_COMMA_X           = 0x95      # sta zp,x
OPCODE_DEX                      = 0xca      # dex
OPCODE_INX                      = 0xe8      # inx
OPCODE_BNE                      = 0xd0      # bne loop

# Global snippets array
snippets = []

# ************************************************************************************************
def register_snippet(fn, snippet):
    snippets.append((fn, snippet6502.parse_snippet(snippet)))

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
    if bytes_to_copy == None:
        bytes_to_copy = p.get_memory("start_count")
        assert bytes_to_copy == None        # DEBUG!

    if not is_load_indirect:
        source_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = make_subtract(source_label, offset)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                source_label = make_add(new_expression, 1)
        source_label = utils.LazyString(" from %s", source_label)
        #if bytes_to_copy == None:
        #    source_label = utils.LazyString("%s+%s", source_label, reg.upper())

    if not is_store_indirect:
        dest_label = p.get_expr('other', label_offset=0, final_offset=offset)

        if offset:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = make_subtract(dest_label, offset)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                dest_label = make_add(new_expression, 1)
        dest_label = utils.LazyString(" to %s", dest_label)
        #if bytes_to_copy == None:
        #    dest_label = utils.LazyString("%s+%s", dest_label, reg.upper())

    offset_string = ""

    if bytes_to_copy != None:
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

    def late_formatter():
        if bytes_to_copy != None:
            bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
        else:
            bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"
        return "This loop copies{0}{1}{2}".format(bytes_to_copy_string, source_label, dest_label)

    disassembly.comment_binary(comment_loc, utils.LazyString("%s", late_formatter), indent=1, align=Align.AFTER_LABEL)

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
    if start_count == None:
        start_count = p.get_memory("start_count")
    bytes_to_copy       = start_count - end_count + 1  if start_count else None

    if not is_load_indirect:
        source_label = p.get_expr('addr', label_offset=0, final_offset=end_count)

        if end_count:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = make_subtract(source_label, end_count)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                source_label = make_add(new_expression, 1)
        source_label = utils.LazyString(" from %s", source_label)
        #if bytes_to_copy == None:
        #    source_label = utils.LazyString("%s+%s", source_label, reg.upper())

    if not is_store_indirect:
        dest_label = p.get_expr('other', label_offset=0, final_offset=end_count)

        if end_count:
            dest_binary_addr = p.get_binary_address('store')+1
            proposed_expression = make_subtract(dest_label, end_count)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                dest_label = make_add(new_expression, 1)
        dest_label = utils.LazyString(" to %s", dest_label)
        #if bytes_to_copy == None:
        #    dest_label = utils.LazyString("%s+%s", dest_label, reg.upper())

    offset_string = str(end_count)

    def late_formatter():
        if bytes_to_copy != None:
            bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
        else:
            bytes_to_copy_string = " " + reg.upper() + offset_string + " bytes of memory"
        return "This loop copies{0}{1}{2}".format(bytes_to_copy_string, source_label, dest_label)

    disassembly.comment_binary(comment_loc, utils.LazyString("%s", late_formatter), indent=1, align=Align.AFTER_LABEL)


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
    if start_count == None:
        start_count = p.get_memory("start_count")
        if start_count == None:
            return

    bytes_to_copy = end_count - start_count

    if not is_load_indirect:
        source_label = p.get_expr('addr', label_offset=0, final_offset=start_count)

        source_binary_addr = p.get_binary_address('load')+1
        proposed_expression = make_subtract(source_label, start_count)
        new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
        if new_expression != proposed_expression:
            source_label = make_subtract(new_expression, start_count)
        source_label = utils.LazyString(" from %s", source_label)

    if not is_store_indirect:
        dest_label = p.get_expr('other', label_offset=0, final_offset=start_count)

        dest_binary_addr = p.get_binary_address('store')+1
        proposed_expression = make_subtract(dest_label, start_count)
        new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
        if new_expression != proposed_expression:
            dest_label = make_subtract(new_expression, start_count)
        dest_label = utils.LazyString(" to %s", dest_label)

    def late_formatter():
        if bytes_to_copy != None:
            bytes_to_copy_string = " " + utils.count_with_units(bytes_to_copy, "byte", "bytes"+ " of memory")
        else:
            bytes_to_copy_string = " some bytes of memory"
        return "This loop copies{0}{1}{2}".format(bytes_to_copy_string, source_label, dest_label)

    disassembly.comment_binary(comment_loc, utils.LazyString("%s", late_formatter), indent=1, align=Align.AFTER_LABEL)

# ************************************************************************************************
def comment_add_to_y(p):
    disassembly.comment_binary(p.get_start_loc(), "add {0} to Y".format(p.get_memory("nn")), indent=1, align=Align.INLINE)

# ************************************************************************************************
def comment_set_memory_r_loop(p, reg):
    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    comment_loc             = p.get_start_loc()
    is_stop_at_zero         = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL
    state                   = p.get_state('comment')
    is_store_indirect       = p.get_memory('zp')   # This is treated as a flag, being None if 'zp' isn't found
    loop_has_one_reference  = p.num_references('loop') == 1
    bytes_to_set            = state.optimistic[reg].value if state and state.optimistic[reg] and loop_has_one_reference else None
    to_value                = state.optimistic['a'].value if state and state.optimistic['a'] and loop_has_one_reference else None
    offset                  = 1 if is_stop_at_zero else 0
    dest_label              = ""
    to_value_string         = ""

    if not is_stop_at_zero:
        bytes_to_set += 1

    if to_value != None:
        to_value_string = " to {0}".format(to_value)

    if not is_store_indirect:
        dest_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            dest_binary_addr = p.get_binary_address('loop')+1
            proposed_expression = make_subtract(dest_label, offset)
            new_expression = classification.add_expression(dest_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                dest_label = make_add(new_expression, 1)
        dest_label = utils.LazyString(" at %s", dest_label)

    def late_formatter():
        if bytes_to_set != None:
            bytes_to_set_string = " " + utils.count_with_units(bytes_to_set, "byte", "bytes"+ " of memory")
        else:
            reg_with_offset_string = reg.upper() if offset != 0 else reg+"+1"
            bytes_to_set_string = " {0} bytes of memory".format(reg_with_offset_string)
        return "This loop sets{0}{1}{2}".format(bytes_to_set_string, dest_label, to_value_string)

    disassembly.comment_binary(comment_loc, utils.LazyString("%s", late_formatter), indent=1, align=Align.AFTER_LABEL)

# ************************************************************************************************
def comment_set_memory_x_loop(p):
    comment_set_memory_r_loop(p, 'x')

# ************************************************************************************************
def comment_set_memory_y_loop(p):
    comment_set_memory_r_loop(p, 'y')

# ************************************************************************************************
# ************************************************************************************************
# ************************************************************************************************
register_snippet(comment_memory_copy_loop, """
; memory copy, using X as the loop counter

comment
?   ldx #start_count
loop
load
    lda addr,x | lda (zp1),x
store
    sta other,x | sta (zp2),x
update
    dex
branch
    bpl loop | bne loop
""")

register_snippet(comment_memory_copy_loop, """
; memory copy, using X as the loop counter

comment
?   ldx #start_count
loop
load
    lda addr,x | lda (zp1),x
store
    sta other,x | sta (zp2),x
update
    dex
branch
    bpl loop | bne loop
""")

register_snippet(comment_memory_copy_loop, """
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

register_snippet(comment_memory_copy_with_limited_end_loop, """
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


register_snippet(comment_memory_copy_with_limited_end_loop, """
; memory copy with final counter check, using X as the loop counter

comment
?   ldx #start_count
loop
load
    lda addr,x | lda (zp1),x
store
    sta other,x | sta (zp2),x
update
    dex
    cpx #end_count
branch
    bcs loop
""")

register_snippet(comment_memory_copy_increment, """
; memory copy increasing loop counter, using X as the loop counter
comment
?    ldx #start_count
loop
load
    lda addr,x | lda (zp1),x
store
    sta other,x | sta (zp2),x
update
    inx
    cpx #end_count
branch
    bne loop | bcc loop
""")

register_snippet(comment_memory_copy_increment, """
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

register_snippet("push flags,A,X,Y onto the stack", """
    php
    pha
    txa
    pha
    tya
    pha
""")

register_snippet("pull flags,A,X,Y from the stack", """
    pla
    tay
    pla
    tax
    pla
    plp
""")

register_snippet("push A,X,Y onto the stack", """
    pha
    txa
    pha
    tya
    pha
""")

register_snippet("pull A,X,Y from the stack", """
    pla
    tay
    pla
    tax
    pla
""")

register_snippet("push flags,A,Y,X onto the stack", """
    php
    pha
    tya
    pha
    txa
    pha
""")

register_snippet("pull flags,A,Y,X from the stack", """
    pla
    tax
    pla
    tay
    pla
    plp
""")

register_snippet("push A,Y,X onto the stack", """
    pha
    tya
    pha
    txa
    pha
""")

register_snippet("pull A,Y,X from the stack", """
    pla
    tax
    pla
    tay
    pla
""")

register_snippet("push X,Y onto the stack", """
    txa
    pha
    tya
    pha
""")

register_snippet("pull X,Y from the stack", """
    pla
    tay
    pla
    tax
""")

register_snippet("push Y,X onto the stack", """
    tya
    pha
    txa
    pha
""")

register_snippet("pull Y,X from the stack", """
    pla
    tax
    pla
    tay
""")

register_snippet("push A,X onto the stack", """
    pha
    txa
    pha
""")

register_snippet("pull A,X from the stack", """
    pla
    tax
    pla
""")

register_snippet("push A,Y onto the stack", """
    pha
    tya
    pha
""")

register_snippet("pull A,Y from the stack", """
    pla
    tay
    pla
""")

register_snippet(comment_add_to_y, """
    tya
    clc
    adc #nn
    tay
""")

register_snippet(comment_set_memory_x_loop, """
comment
loop
    sta addr,y | sta (zp),y
    iny
    dex
branch
    bne loop | bpl loop
""")

register_snippet(comment_set_memory_y_loop, """
comment
loop
    sta addr,x | sta (zp),x
    inx
    dey
branch
    bne loop | bpl loop
""")
