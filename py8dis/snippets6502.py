import classification
import disassembly
import snippet6502
import utils
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo

# Opcodes
OPCODE_LDA_ZP_COMMA_X           = 0xb5      # lda zp,x
OPCODE_STA_ZP_COMMA_X           = 0x95      # sta zp,x
OPCODE_DEX                      = 0xca      # dex
OPCODE_INX                      = 0xe8      # inx
OPCODE_BNE                      = 0xd0      # bne loop

# Global snippets array
snippets = []

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
    bytes_to_copy       = state[reg].value if state and state[reg] else None
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
    start_count         = state[reg].value if state and state[reg] else None
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
    start_count         = state[reg].value if state and state[reg] else None
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

    comment_loc         = p.get_start_loc()
    is_stop_at_zero     = p.get_memory('branch') == OPCODE_BNE      # BNE or BPL
    state               = p.get_state('comment')
    is_store_indirect   = p.get_memory('zp')   # This is treated as a flag, being None if 'zp' isn't found
    bytes_to_set        = state[reg].value if state and state[reg] else None
    offset              = 1 if is_stop_at_zero else 0
    dest_label          = ""
    to_value_string     = ""

    if bytes_to_set != None:
        to_value_string = " to {0}".format(bytes_to_set)

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
            bytes_to_set_string = " some bytes of memory"
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
snippets.append((comment_memory_copy_loop, snippet6502.parse_snippet("""
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
""")))


snippets.append((comment_memory_copy_loop, snippet6502.parse_snippet("""
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
""")))


snippets.append((comment_memory_copy_with_limited_end_loop, snippet6502.parse_snippet("""
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
""")))


snippets.append((comment_memory_copy_with_limited_end_loop, snippet6502.parse_snippet("""
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
""")))


snippets.append((comment_memory_copy_increment, snippet6502.parse_snippet("""
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
""")))

snippets.append((comment_memory_copy_increment, snippet6502.parse_snippet("""
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
""")))

snippets.append(("push flags,A,X,Y onto the stack", snippet6502.parse_snippet("""
    php
    pha
    txa
    pha
    tya
    pha
""")))

snippets.append(("pull flags,A,X,Y from the stack", snippet6502.parse_snippet("""
    pla
    tay
    pla
    tax
    pla
    plp
""")))

snippets.append(("push A,X,Y onto the stack", snippet6502.parse_snippet("""
    pha
    txa
    pha
    tya
    pha
""")))

snippets.append(("pull A,X,Y from the stack", snippet6502.parse_snippet("""
    pla
    tay
    pla
    tax
    pla
""")))

snippets.append(("push flags,A,Y,X onto the stack", snippet6502.parse_snippet("""
    php
    pha
    tya
    pha
    txa
    pha
""")))

snippets.append(("pull flags,A,Y,X from the stack", snippet6502.parse_snippet("""
    pla
    tax
    pla
    tay
    pla
    plp
""")))

snippets.append(("push A,Y,X onto the stack", snippet6502.parse_snippet("""
    pha
    tya
    pha
    txa
    pha
""")))

snippets.append(("pull A,Y,X from the stack", snippet6502.parse_snippet("""
    pla
    tax
    pla
    tay
    pla
""")))

snippets.append(("push X,Y onto the stack", snippet6502.parse_snippet("""
    txa
    pha
    tya
    pha
""")))

snippets.append(("pull X,Y from the stack", snippet6502.parse_snippet("""
    pla
    tay
    pla
    tax
""")))

snippets.append(("push Y,X onto the stack", snippet6502.parse_snippet("""
    tya
    pha
    txa
    pha
""")))

snippets.append(("pull Y,X from the stack", snippet6502.parse_snippet("""
    pla
    tax
    pla
    tay
""")))

snippets.append(("push A,X onto the stack", snippet6502.parse_snippet("""
    pha
    txa
    pha
""")))

snippets.append(("pull A,X from the stack", snippet6502.parse_snippet("""
    pla
    tax
    pla
""")))

snippets.append(("push A,Y onto the stack", snippet6502.parse_snippet("""
    pha
    tya
    pha
""")))

snippets.append(("pull A,Y from the stack", snippet6502.parse_snippet("""
    pla
    tay
    pla
""")))

snippets.append((comment_add_to_y, snippet6502.parse_snippet("""
    tya
    clc
    adc #nn
    tay
""")))

snippets.append((comment_set_memory_x_loop, snippet6502.parse_snippet("""
loop
    sta addr,y | sta (zp),y
    iny
    dex
branch
    bne loop | bpl loop
""")))

snippets.append((comment_set_memory_y_loop, snippet6502.parse_snippet("""
loop
    sta addr,x | sta (zp),x
    inx
    dey
branch
    bne loop | bpl loop
""")))
