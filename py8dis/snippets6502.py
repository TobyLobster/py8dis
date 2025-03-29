import classification
import disassembly
import snippet6502
import utils
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo

# Opcodes
OPCODE_LDA_ZP_COMMA_X           = 0xb5      # lda zp,x
OPCODE_STA_ZP_COMMA_X           = 0x95      # sta zp,x
#OPCODE_LDA_BRACKETS_ZP_COMMA_Y  = 0xb1      # lda (zp),y
#OPCODE_STA_BRACKETS_ZP_COMMA_Y  = 0x91      # sta (zp),y
OPCODE_DEX                      = 0xca      # dex
OPCODE_BNE                      = 0xd0      # bne loop

# Global snippets array
snippets = []

def comment_memory_copy_loop(p):
    # e.g. "This loop copies 8 bytes from source+Y to dest+Y"

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
    loop_counter        = state[reg].value if state and state[reg] else None

    if not is_load_indirect:
        source_label = p.get_expr('addr', label_offset=0, final_offset=offset)

        if offset:
            source_binary_addr = p.get_binary_address('load')+1
            proposed_expression = make_subtract(source_label, offset)
            new_expression = classification.add_expression(source_binary_addr, proposed_expression, force=False)
            if new_expression != proposed_expression:
                source_label = make_add(new_expression, 1)
        source_label = utils.LazyString(" from %s", source_label)
        #if loop_counter == None:
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
        #if loop_counter == None:
        #    dest_label = utils.LazyString("%s+%s", dest_label, reg.upper())

    offset_string = ""

    if loop_counter != None:
        if not is_stop_at_zero:
            # "bpl loop"
            if loop_counter > 128:
                # "bpl loop" and initial value is 129 or higher then the loop will only happen once.
                # This is for completeness/correctness only - why you would write a loop like this?
                loop_counter = 1
            else:
                # Stop when reg becomes 255
                loop_counter += 1

        # with a loop counter initialised to zero, we actually loop 256 times
        if is_stop_at_zero and (loop_counter == 0):
            # "bne loop"
            loop_counter = 256
    else:
        if not is_stop_at_zero:
            offset_string = "+1"

    def late_formatter():
        if loop_counter != None:
            loop_counter_string = " " + utils.count_with_units(loop_counter, "byte", "bytes"+ " of memory")
        else:
            loop_counter_string = " " + reg.upper() + offset_string + " bytes of memory"
        return "This loop copies{0}{1}{2}".format(loop_counter_string, source_label, dest_label)

    disassembly.comment_binary(comment_loc, utils.LazyString("%s", late_formatter), indent=1, align=Align.AFTER_LABEL)

snippets.append((snippet6502.parse_snippet("""
comment
?    ldx #nn
loop
load
    lda addr,x | lda (zp1),x
store
    sta other,x | sta (zp2),x
update
    dex
branch
    bpl loop | bne loop
"""
), comment_memory_copy_loop))

snippets.append((snippet6502.parse_snippet("""
comment
?    ldy #nn
loop
load
    lda addr,y | lda (zp1),y
store
    sta other,y | sta (zp2),y
update
    dey
branch
    bpl loop | bne loop
"""
), comment_memory_copy_loop))

