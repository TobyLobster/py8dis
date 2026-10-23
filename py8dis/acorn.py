"""
Acorn specific functions.
"""

from commands import *
from classification import INSIDE_A_CLASSIFICATION
import config
import session
import trace
import utils
import classification
import machinetype
import sys
from memorymanager import BinaryAddr, RuntimeAddr
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from snippets6502 import register_snippet, register_code_snippet, register_data_snippet, OPCODE_TXA, OPCODE_TYA

# The data tables (OS call names, INKEY numbers etc), which control files can
# use as e.g. acorn.inkey_enum
from acorntables import *


# ************************************************************************************************
def pre_trace_writing_to_vector(p):
    p.entry()

    addr1 = p.get_memory('first_store', 1) + 256*p.get_memory('first_store', 2)
    addr2 = p.get_memory('second_store', 1) + 256*p.get_memory('second_store', 2)
    nn1_addr = p.get_binary_address('nn1')
    nn2_addr = p.get_binary_address('nn2')
    nn1 = p.get_memory('nn1')
    nn2 = p.get_memory('nn2')
    end = p.get_binary_location('end')

    # The number of handlers found so far for each vector, for naming them
    vector_handler_count = session.current().extras.setdefault("acorn.vector_handler_count", {})

    if addr1 == (addr2 + 1) and ((addr2 & 1) == 0):
        # swap addr1 and addr2, so that addr1 is the lower
        addr1, addr2 = addr2, addr1
        nn1, nn2 = nn2, nn1
        nn1_addr, nn2_addr = nn2_addr, nn1_addr

    if addr2 == (addr1 + 1) and ((addr1 & 1) == 0):
        if addr1 in vectors:
            new_addr = nn1 + 256 * nn2

            # Get a label name if it already exists (just choose the first explicit name for lack of a better choice)
            if new_addr in session.current().labels.labels and session.current().labels.labels[new_addr].explicit_names:
                for move_id, name_list in session.current().labels.labels[new_addr].explicit_names.items():
                    label_name = name_list[0].text
                    break
            else:
                # Create new label name
                if addr1 not in vector_handler_count:
                    label_name = "handle_{0}".format(vectors[addr1])
                    vector_handler_count[addr1] = 2
                else:
                    label_name = "handle_{0}_{1}".format(vectors[addr1], vector_handler_count[addr1])
                    vector_handler_count[addr1] += 1
                label(new_addr, label_name)

            p.entry(RuntimeAddr(new_addr))

            if not p.has_explicit_label(p.get_start_loc()):
                p.blank_once(p.get_start_loc())
            disassembly.comment_binary(p.get_start_loc(), "Set {0} to '{1}'".format(vector_descriptions[addr1], label_name), indent=1, align=Align.AFTER_LABEL, auto_generated=True)
            p.blank_once(end)

            # Get addresses of nn1 and nn2
            nn1_addr_runtime = movemanager.b2r(nn1_addr)
            nn2_addr_runtime = movemanager.b2r(nn2_addr)

            expr(nn1_addr_runtime, make_lo(label_name))
            expr(nn2_addr_runtime, make_hi(label_name))

# ************************************************************************************************
def comment_print_tab(p):
    def get_coord_str(operand_label, instruction_label):
        coord = p.get_memory(operand_label)
        if coord is None:
            opcode = p.get_memory(instruction_label)
            if opcode == OPCODE_TXA:
                coord = 'X'
            elif opcode == OPCODE_TYA:
                coord = 'Y'
            else:
                coord = '?'
        else:
            coord = str(coord)
        return coord
    x = get_coord_str('nn1', 'transfer1')
    y = get_coord_str('nn2', 'transfer2')
    disassembly.comment_binary(p.get_start_loc(), "Position text cursor at ({0},{1})".format(x,y), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_print_message(p):
    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    disassembly.comment_binary(p.get_start_loc(), "print message", indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_print_repeated_character(p):
    if not p.check_branch_matches('loop1') and not p.check_branch_matches('loop2'):
        return
    cc = p.get_memory('nn1')
    if cc is None:
        cc = 'A'

    disassembly.comment_binary(p.get_start_loc(), "print character {0} repeatedly".format(cc), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_screen_addresses(p):
    low_addr = p.get_binary_address('low')
    high_addr = p.get_binary_address('high')

    is_word = low_addr is None and high_addr is None
    if is_word:
        low_addr = p.get_start_loc().binary_addr
        high_addr = low_addr + 1
        offset_to_next_entry = 2
    else:
        offset_to_next_entry = 1

    start = p.get_memory(low_addr) + 256*p.get_memory(high_addr)
    second = p.get_memory(low_addr+offset_to_next_entry) + 256*p.get_memory(high_addr+offset_to_next_entry)
    offset = second - start

    # get runtime addresses
    low_addr_runtime = movemanager.b2r(low_addr)
    high_addr_runtime = movemanager.b2r(high_addr)

    for i in range(0,32):
        exp = make_add(make_hex(start), make_multiply(i, make_hex(offset)))
        if not is_word:
            if classification.get_classification(low_addr_runtime+i) is None and classification.get_classification(high_addr_runtime+i) is None:
                byte(low_addr_runtime+i, 1)
                byte(high_addr_runtime+i, 1)
                expr(low_addr_runtime+i, make_lo(exp))
                expr(high_addr_runtime+i, make_hi(exp))
        else:
            if classification.get_classification(low_addr_runtime+i*2) is None:
                word(low_addr_runtime+i*2, 1)
                expr(low_addr_runtime+i*2, exp)

    if is_word:
        disassembly.comment_binary(low_addr, "table of screen addresses for each character row", indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    else:
        if low_addr:
            disassembly.comment_binary(low_addr, "table of screen addresses for each character row (low bytes)", indent=1, align=Align.AFTER_LABEL, auto_generated=True)
        if high_addr:
            disassembly.comment_binary(high_addr, "table of screen addresses for each character row (high bytes)", indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
def comment_screen_offsets(p):
    low_addr = p.get_binary_address('low')
    high_addr = p.get_binary_address('high')
    if low_addr:
        disassembly.comment_binary(low_addr, "table of offsets for each character row (low bytes)", indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    if high_addr:
        disassembly.comment_binary(high_addr, "table of offsets for each character row (high bytes)", indent=1, align=Align.AFTER_LABEL, auto_generated=True)

# ************************************************************************************************
# ************************************************************************************************
# ************************************************************************************************
def register_snippets():
    """Register acorn's snippets with the current session (called by
    mos_labels(), once per session)."""
    extras = session.current().extras
    if extras.get("acorn.snippets_registered"):
        return
    extras["acorn.snippets_registered"] = True

    register_code_snippet(comment_print_tab, """
    lda #$1f
    jsr $ffee
transfer1
    lda #nn1 | txa | tya
    jsr $ffee
transfer2
    lda #nn2 | txa | tya
    jsr $ffee
""")

    register_code_snippet(comment_print_message, """
?   ldy #nn1 | ldy zp | ldy zp,x | ldy addr | ldy addr,x
loop
    lda message,y | lda zp,y | lda (zp1),y
?   bmi other | beq other
    jsr $ffee
    iny | dey
?   cpy #nn2
    bne loop | bpl loop
""")

    register_code_snippet(comment_print_message, """
?   ldx #nn1 | ldx zp | ldx zp,y | ldx addr | ldx addr,y
loop
    lda message,x | lda zp,x | lda (zp1,x)
?   bmi other | beq other
    jsr $ffee
    inx | dex
?   cpx #nn2
    bne loop | bpl loop
""")

    register_code_snippet(comment_print_repeated_character, """
loop1
?   lda #nn1 | lda addr | lda zp | ldx #nn | ldx addr | ldx zp
?   lda #nn1 | lda addr | lda zp | ldx #nn | ldx addr | ldx zp
loop2
    jsr $ffee
    dex
    bne loop1 | bne loop2 | bpl loop1 | bpl loop2
""")

    # e.g.:
    #low
    #    !byte $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0, $00, $40, $80, $c0
    #high
    #    !byte $58, $59, $5a, $5b, $5d, $5e, $5f, $60, $62, $63, $64, $65, $67, $68, $69, $6a, $6c, $6d, $6e, $6f, $71, $72, $73, $74, $76, $77, $78, $79, $7b, $7c, $7d, $7e

    for pair in [(0x3000, 0x280), (0x5800, 0x140), (0x0, 0x280), (0x0, 0x140)]:
        start = pair[0]
        offset = pair[1]
        for length in range(32,33):
            for order in [('!byte', 2, 'high', 'low'), ('!byte', 2, 'low', 'high'), ('!word', 3, '', '')]:
                snip = ""
                for index in range(order[1],4):
                    snip += "\n" + order[index] + "\n    {0}".format(order[0])
                    for i in range(length):
                        v = start + i*offset
                        if order[index] == 'low':
                            snip += " $"+hex(v & 255)[2:]+","
                        elif order[index] == 'high':
                            snip += " $"+hex(v >> 8)[2:]+","
                        else:
                            snip += " $"+hex(v)[2:]+","

                #utils.debug("Snip:{0}".format(snip))
                if start == 0:
                    register_data_snippet(comment_screen_offsets, snip)
                else:
                    register_data_snippet(comment_screen_addresses, snip)

    # ********************************************************************************************
    # ********************************************************************************************
    # ********************************************************************************************
    register_snippet(pre_trace_writing_to_vector, None, """
    lda #nn1
first_store
    sta $200 | sta $201 | sta $202 | sta $203 | sta $204 | sta $205 | sta $206 | sta $207 | sta $208 | sta $209 | sta $20a | sta $20b | sta $20c | sta $20d | sta $20e | sta $20f | sta $210 | sta $211 | sta $212 | sta $213 | sta $214 | sta $215 | sta $216 | sta $217 | sta $218 | sta $219 | sta $21a | sta $21b | sta $21c | sta $21d | sta $21e | sta $21f | sta $220 | sta $221 | sta $222 | sta $223 | sta $224 | sta $225 | sta $226 | sta $227 | sta $228 | sta $229 | sta $22a | sta $22b | sta $22c | sta $22d | sta $22e | sta $22f | sta $230 | sta $231 | sta $232 | sta $233 | sta $234 | sta $235
    lda #nn2
second_store
    sta $200 | sta $201 | sta $202 | sta $203 | sta $204 | sta $205 | sta $206 | sta $207 | sta $208 | sta $209 | sta $20a | sta $20b | sta $20c | sta $20d | sta $20e | sta $20f | sta $210 | sta $211 | sta $212 | sta $213 | sta $214 | sta $215 | sta $216 | sta $217 | sta $218 | sta $219 | sta $21a | sta $21b | sta $21c | sta $21d | sta $21e | sta $21f | sta $220 | sta $221 | sta $222 | sta $223 | sta $224 | sta $225 | sta $226 | sta $227 | sta $228 | sta $229 | sta $22a | sta $22b | sta $22c | sta $22d | sta $22e | sta $22f | sta $230 | sta $231 | sta $232 | sta $233 | sta $234 | sta $235
end
""")

    register_snippet(pre_trace_writing_to_vector, None, """
    ldx #nn1
    ldy #nn2
first_store
    stx $200 | stx $201 | stx $202 | stx $203 | stx $204 | stx $205 | stx $206 | stx $207 | stx $208 | stx $209 | stx $20a | stx $20b | stx $20c | stx $20d | stx $20e | stx $20f | stx $210 | stx $211 | stx $212 | stx $213 | stx $214 | stx $215 | stx $216 | stx $217 | stx $218 | stx $219 | stx $21a | stx $21b | stx $21c | stx $21d | stx $21e | stx $21f | stx $220 | stx $221 | stx $222 | stx $223 | stx $224 | stx $225 | stx $226 | stx $227 | stx $228 | stx $229 | stx $22a | stx $22b | stx $22c | stx $22d | stx $22e | stx $22f | stx $230 | stx $231 | stx $232 | stx $233 | stx $234 | stx $235
second_store
    sty $200 | sty $201 | sty $202 | sty $203 | sty $204 | sty $205 | sty $206 | sty $207 | sty $208 | sty $209 | sty $20a | sty $20b | sty $20c | sty $20d | sty $20e | sty $20f | sty $210 | sty $211 | sty $212 | sty $213 | sty $214 | sty $215 | sty $216 | sty $217 | sty $218 | sty $219 | sty $21a | sty $21b | sty $21c | sty $21d | sty $21e | sty $21f | sty $220 | sty $221 | sty $222 | sty $223 | sty $224 | sty $225 | sty $226 | sty $227 | sty $228 | sty $229 | sty $22a | sty $22b | sty $22c | sty $22d | sty $22e | sty $22f | sty $230 | sty $231 | sty $232 | sty $233 | sty $234 | sty $235
end
""")


# ************************************************************************************************
def xy_addr(x_addr, y_addr):
    """Given two binary addresses holding the low byte and high byte of an address,
    output expressions for each and return the address."""

    if x_addr is not None and y_addr is not None:
        assert isinstance(x_addr, BinaryAddr)
        assert isinstance(y_addr, BinaryAddr)
        if (memory_binary[x_addr] is None) or (memory_binary[y_addr] is None):
            return None
        label = get_label((memory_binary[y_addr] << 8) | memory_binary[x_addr], x_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
        x_runtime_addr = None if x_addr is None else movemanager.b2r(x_addr)
        y_runtime_addr = None if y_addr is None else movemanager.b2r(y_addr)

        if isinstance(classification.get_classification(x_addr), classification.Word) and (y_runtime_addr == (x_runtime_addr+1)):
            # If memory is classified as Word, we can have the expression be for the whole address
            auto_expr(x_runtime_addr, label)
        else:
            # If memory is classified as a byte or 'INSIDE_A_CLASSIFICATION' (e.g. an operand of an instruction) then code them as individual bytes
            if isinstance(classification.get_classification(x_addr), classification.Byte) or (classification.get_classification(x_addr) is INSIDE_A_CLASSIFICATION):
                auto_expr(x_runtime_addr, make_lo(label))
            if isinstance(classification.get_classification(y_addr), classification.Byte) or (classification.get_classification(y_addr) is INSIDE_A_CLASSIFICATION):
                auto_expr(y_runtime_addr, make_hi(label))

        return RuntimeAddr((memory_binary[y_addr] << 8) | memory_binary[x_addr])
    return None


def enum_lookup(reg_binary_addr, e, comment=None):
    """Given a binary_addr and a dictionary, read the byte at the address and look
    it up in the dictionary and use the result to create a constant and use it as
    an expression.
    """

    if reg_binary_addr is None:
        return None
    r = memorymanager.memory_binary[reg_binary_addr]
    if r in e:
        constant(r, e[r])
        runtime_addr = movemanager.b2r(reg_binary_addr)
        auto_expr(runtime_addr, e[r])
    if comment is not None:
        auto_comment(r, comment)
    return r

def oswrsc_hook(runtime_addr, state, subroutine):
    a_adjust_addr = state.optimistic['a'].previous_adjust
    a_runtime_adjust = None if a_adjust_addr is None else movemanager.b2r(a_adjust_addr)
    y_adjust_addr = state.optimistic['y'].previous_adjust
    y_runtime_adjust = None if y_adjust_addr is None else movemanager.b2r(y_adjust_addr)

    auto_comment(a_runtime_adjust, "A=value to be written", align=Align.INLINE)
    auto_comment(y_runtime_adjust, "Y=offset from base address", align=Align.INLINE)
    auto_comment(runtime_addr, "Write byte to screen", align=Align.INLINE)

def osrdsc_hook(runtime_addr, state, subroutine):
    y_adjust_addr = state.optimistic['y'].previous_adjust
    y_runtime_adjust = None if y_adjust_addr is None else movemanager.b2r(y_adjust_addr)
    auto_comment(y_runtime_adjust, "Y=ROM number", align=Align.INLINE)

    # Post-exit
    a_runtime_next_use = None if state.next_use['a'] is None else movemanager.b2r(state.next_use['a'])
    auto_comment(a_runtime_next_use, "A=byte read", align=Align.INLINE)
    auto_comment(runtime_addr, "Read byte from ROM Y or screen", align=Align.INLINE)

def oseven_hook(runtime_addr, state, subroutine):
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()
    y_addr_pessimistic = state.pessimistic['y'].get_previous_load_imm_operand()

    # label the optimistic load immediate
    if y_addr_optimistic is not None:
        event_number = memory_binary[y_addr_optimistic]
        enum_lookup(y_addr_optimistic, event_enum, "Y=event number")

    if y_addr_pessimistic is None:
        auto_comment(runtime_addr, "Generate event Y", align=Align.INLINE)
        return

    event_number = memory_binary[y_addr_pessimistic]
    if event_number in event_names:
        com = "Generate event Y='" + event_names[event_number] + "'"
    else:
        com = "Generate an unknown event Y"
    auto_comment(runtime_addr, com, align=Align.INLINE)

def osfind_hook(runtime_addr, state, subroutine):
    a_addr_optimistic = state.optimistic['a'].get_previous_load_imm_operand()
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    x_addr_pessimistic = state.pessimistic['x'].get_previous_load_imm_operand()
    y_addr_pessimistic = state.pessimistic['y'].get_previous_load_imm_operand()

    enum_lookup(a_addr_optimistic, osfind_enum)

    com = "Open or close file(s)"
    if a_addr_pessimistic is not None:
        action_pessimistic = memory_binary[a_addr_pessimistic]
        if action_pessimistic == 0:
            com = "Close one or all files"
            if y_addr_pessimistic is not None:
                com = "Close file Y"
                y = memory_binary[y_addr_pessimistic]
                if y == 0:
                    com = "Close all files (Y=0)"
        elif action_pessimistic == 64:
            com = "Open file for input (A=64)"
        elif action_pessimistic == 128:
            com = "Open file for output (A=128)"
        elif action_pessimistic == 192:
            com = "Open file for random access (A=192)"

        if action_pessimistic != 0:
            xy_addr(x_addr_pessimistic, y_addr_pessimistic)

            # Post-exit
            a_runtime_next_use = None if state.next_use['a'] is None else movemanager.b2r(state.next_use['a'])
            auto_comment(a_runtime_next_use, "A=file handle (or zero on failure)", align=Align.INLINE)

    auto_comment(runtime_addr, com, align=Align.INLINE)

def osrdch_hook(runtime_addr, state, subroutine):
    auto_comment(runtime_addr, "Read a character from the current input stream", align=Align.INLINE)

    # Post-exit
    a_runtime_next_use = None if state.next_use['a'] is None else movemanager.b2r(state.next_use['a'])
    auto_comment(a_runtime_next_use, "A=character read", align=Align.INLINE)

def osgbpb_hook(runtime_addr, state, subroutine):
    a_addr_optimistic  = state.optimistic['a'].get_previous_load_imm_operand()
    #x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    #y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    x_addr_pessimistic = state.pessimistic['x'].get_previous_load_imm_operand()
    y_addr_pessimistic = state.pessimistic['y'].get_previous_load_imm_operand()

    # label enumeration optimistically
    enum_lookup(a_addr_optimistic, osgbpb_enum)

    # get specific action pessimistically
    action_pessimistic = enum_lookup(a_addr_pessimistic, osgbpb_enum)
    block_addr = xy_addr(x_addr_pessimistic, y_addr_pessimistic)

    if block_addr is not None:
        if action_pessimistic == 8:
            auto_comment(block_addr, "osgbpb block: disc cycle number", align=Align.INLINE)
            auto_comment(RuntimeAddr(block_addr + 1), "address for returned data (4 bytes)", align=Align.INLINE)
            auto_comment(RuntimeAddr(block_addr + 5), "number of filenames (4 bytes)", align=Align.INLINE)
        else:
            auto_comment(block_addr, "osgbpb block: file handle", align=Align.INLINE)
            auto_comment(RuntimeAddr(block_addr + 1), "start address of data (4 bytes)", align=Align.INLINE)
            auto_comment(RuntimeAddr(block_addr + 5), "number of bytes to transfer (4 bytes)", align=Align.INLINE)
        auto_comment(RuntimeAddr(block_addr + 9), "sequential pointer value to be used (4 bytes)", align=Align.INLINE)


    if action_pessimistic in osgbpb_desc:
        auto_comment(runtime_addr, osgbpb_desc[action_pessimistic] + " (A=%d)" % action_pessimistic, align=Align.INLINE)
    elif action_pessimistic is not None:
        auto_comment(runtime_addr, "unknown OSGBPB call, (A=%d)" % action_pessimistic, align=Align.INLINE)
    else:
        auto_comment(runtime_addr, "Read or write multiple bytes to an open file", align=Align.INLINE)

def osbput_hook(runtime_addr, state, subroutine):
    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    y_addr_optimistic  = state.optimistic['y'].previous_adjust
    y_runtime_addr_optimistic = None if y_addr_optimistic is None else movemanager.b2r(y_addr_optimistic)

    if a_addr_pessimistic is not None:
        reg = "A=" + str(memory_binary[a_addr_pessimistic])
    else:
        reg = "A"

    com = "Write a single byte %s to an open file Y" % reg
    auto_comment(runtime_addr, com, align=Align.INLINE)
    auto_comment(y_runtime_addr_optimistic, "Y=file handle", align=Align.INLINE)

def osbget_hook(runtime_addr, state, subroutine):
    y_addr = state.optimistic['y'].previous_adjust
    y_runtime_addr_optimistic = None if y_addr is None else movemanager.b2r(y_addr)

    auto_comment(runtime_addr, "Read a single byte from an open file Y", align=Align.INLINE)
    auto_comment(y_runtime_addr_optimistic, "Y=file handle", align=Align.INLINE)

def osargs_hook(runtime_addr, state, subroutine):
    a_addr_optimistic = state.optimistic['a'].get_previous_load_imm_operand()
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    x_addr_pessimistic = state.pessimistic['x'].get_previous_load_imm_operand()
    y_addr_pessimistic = state.pessimistic['y'].get_previous_load_imm_operand()

    x_adjust_addr_optimistic = state.optimistic['x'].previous_adjust
    y_adjust_addr_optimistic = state.optimistic['y'].previous_adjust

    # Runtime equivalents
    x_runtime_adjust_addr_optimistic = None if x_adjust_addr_optimistic is None else movemanager.b2r(x_adjust_addr_optimistic)
    y_runtime_adjust_addr_optimistic = None if y_adjust_addr_optimistic is None else movemanager.b2r(y_adjust_addr_optimistic)

    a_next_use = state.next_use['a']
    # Equivalent runtime addresses
    a_runtime_next_use = None if a_next_use is None else movemanager.b2r(a_next_use)

    a = None if a_addr_pessimistic is None else memory_binary[a_addr_pessimistic]
    x = None if x_addr_pessimistic is None else memory_binary[x_addr_pessimistic]
    y = None if y_addr_pessimistic is None else memory_binary[y_addr_pessimistic]

    if (a == 0) and (y == 0):
        auto_comment(runtime_addr, "Get filing system number (A=0, Y=0)", align=Align.INLINE)
        auto_comment(a_runtime_next_use, "A=filing system number", align=Align.INLINE)
        auto_comment(a_runtime_next_use,
"""A is the filing system number:
    A=0, no filing system selected
    A=1, 1200 baud CFS
    A=2, 300 baud CFS
    A=3, ROM filing system
    A=4, Disc filing system
    A=5, Network filing system
    A=6, Teletext filing system
    A=7, IEEE filing system
    A=8, ADFS
    A=9, Host filing system
    A=10, Videodisc filing system""", indent=1)

    elif a == 0:
        auto_comment(x_runtime_adjust_addr_optimistic, "X=zero page address for result", align=Align.INLINE)
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=file handle", align=Align.INLINE)

        auto_comment(runtime_addr, "Get sequential file pointer into zero page address X (A=0)", align=Align.INLINE)
    elif (a == 1) and (y == 0):
        auto_comment(x_runtime_adjust_addr_optimistic, "X=zero page address for result", align=Align.INLINE)

        auto_comment(runtime_addr, "Get address of remaining command line into zero page address X (A=1, Y=0)", align=Align.INLINE)
    elif a == 1:
        auto_comment(x_runtime_adjust_addr_optimistic, "X=zero page address to write from", align=Align.INLINE)
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=file handle", align=Align.INLINE)

        auto_comment(runtime_addr, "Write sequential file pointer from zero page address X (A=1)", align=Align.INLINE)
    elif a == 2:
        auto_comment(x_runtime_adjust_addr_optimistic, "X=zero page address for result", align=Align.INLINE)
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=file handle", align=Align.INLINE)

        auto_comment(runtime_addr, "Get length of file into zero page address X (A=2)", align=Align.INLINE)
    elif (a == 255) and (y == 0):
        auto_comment(runtime_addr, "Write any buffered data to all pending files (A=255, Y=0)", align=Align.INLINE)

    elif a == 255:
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=file handle", align=Align.INLINE)

        auto_comment(runtime_addr, "Write any buffered data to file Y", align=Align.INLINE)
    elif a is not None:
        auto_comment(runtime_addr, "Read or write a file's attributes (unknown action A=%d)" % a, align=Align.INLINE)
    else:
        auto_comment(runtime_addr, "Read or write a file's attributes", align=Align.INLINE)

def osnewl_hook(runtime_addr, state, subroutine):
    auto_comment(runtime_addr, "Write newline (characters 10 and 13)", align=Align.INLINE)

def oswrcr_hook(runtime_addr, state, subroutine):
    auto_comment(runtime_addr, "Write carriage return (character 13)", align=Align.INLINE)

def oswrch_hook(runtime_addr, state, subroutine):
    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    if a_addr_pessimistic is not None:
        a = " " + str(memory_binary[a_addr_pessimistic])

        # If OSASCI with A=13, then OSNEWL is called instead
        if subroutine.label_name == "osasci" and memory_binary[a_addr_pessimistic] == 13:
            osnewl_hook(runtime_addr, state, subroutine)
            return
    else:
        a = ""
    auto_comment(runtime_addr, "Write character%s" % a, align=Align.INLINE)

def osfile_hook(runtime_addr, state, subroutine):
    a_addr_optimistic = state.optimistic['a'].get_previous_load_imm_operand()
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()

    # label where the accumulator is being set (optimistically)
    enum_lookup(a_addr_optimistic, osfile_enum)

    # label where the X,Y registers are being set (optimistically)
    xy_addr(x_addr_optimistic, y_addr_optimistic)

    # now label the call to OSFILE itself, pessimistically
    if a_addr_pessimistic is None:
        return

    action_pessimistic = memory_binary[a_addr_pessimistic]

    if action_pessimistic in osfile_descriptions:
        auto_comment(runtime_addr, osfile_descriptions[action_pessimistic] + " (A=%d)" % action_pessimistic, align=Align.INLINE)
    elif action_pessimistic is not None:
        auto_comment(runtime_addr, "unknown OSFILE call (A=%d)" % action_pessimistic, align=Align.INLINE)

def osword_hook(runtime_addr, state, subroutine):
    a_addr_optimistic = state.optimistic['a'].get_previous_load_imm_operand()
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()

    # label where the accumulator is being set (optimistically)
    enum_lookup(a_addr_optimistic, osword_enum)

    # label where the X,Y registers are being set (optimistically)
    block_addr = xy_addr(x_addr_optimistic, y_addr_optimistic)

    # now label the call to OSWORD itself, pessimistically
    if a_addr_pessimistic is None:
        return

    action_pessimistic = memory_binary[a_addr_pessimistic]
    if action_pessimistic in osword_descriptions:
        com = osword_descriptions[action_pessimistic]
        if action_pessimistic >= 16:
            com += " (see https://beebwiki.mdfs.net/OSWORDs)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    # Block descriptions
    if block_addr is not None:
        if action_pessimistic in osword_block_descriptions:
            desc_dict = osword_block_descriptions[action_pessimistic]

            if action_pessimistic == 0:
                input_buffer_addr, _ = movemanager.r2b(block_addr)
                xy_addr(input_buffer_addr, input_buffer_addr+1)

            for i in desc_dict:
                auto_comment(RuntimeAddr(block_addr + i), desc_dict[i], align=Align.INLINE)

    # Post-exit
    if action_pessimistic == 0:
        y_runtime_next_use = None if state.next_use['y'] is None else movemanager.b2r(state.next_use['y'])
        auto_comment(y_runtime_next_use, "Y contains line length, including carriage return if used.", align=Align.INLINE)

def osbyte_rw(x_binary_addr, y_binary_addr):
    com = "Read/Write"
    write_value=None
    if y_binary_addr is not None:
        if memory_binary[y_binary_addr] == 0:
            com = "Write"
            if x_binary_addr is not None:
                write_value = memory_binary[x_binary_addr]
        elif x_binary_addr is not None:
            if (memory_binary[x_binary_addr] == 0) and (memory_binary[y_binary_addr] == 255):
                com = "Read"

    return (com, write_value)

def format_osbyte_rw(x_addr, y_addr, comment_name):
    com, write_value = osbyte_rw(x_addr, y_addr)
    result = com + " " + comment_name
    if write_value is not None:
        result += ", value X=" + str(write_value)

    return result

def key_name(key):
    if key in inkey_enum:
        return "'" + inkey_enum[key][10:].upper() + "'"
    return "an unknown"

def append_bit_string(str, x, bit, result1, result0):
    if len(str) > 0:
        str += "; "
    if (x & (1<<bit)) == 0:
        str += result0
    else:
        str += result1
    return str

def osbyte_hook(runtime_addr, state, subroutine):
    a_addr_optimistic = state.optimistic['a'].get_previous_load_imm_operand()
    a_addr_pessimistic = state.pessimistic['a'].get_previous_load_imm_operand()
    if a_addr_optimistic is None:
        return

    # label the value where the accumulator is set (optimistically)
    enum_lookup(a_addr_optimistic, osbyte_enum)

    # Binary addresses (optimistic)
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()

    x_addr_pessimistic = state.pessimistic['x'].get_previous_load_imm_operand()
    y_addr_pessimistic = state.pessimistic['y'].get_previous_load_imm_operand()

    x_load_addr_optimistic = state.optimistic['x'].previous_load
    y_load_addr_optimistic = state.optimistic['y'].previous_load
    x_adjust_addr_optimistic = state.optimistic['x'].previous_adjust
    y_adjust_addr_optimistic = state.optimistic['y'].previous_adjust

    assert (a_addr_pessimistic == a_addr_optimistic) or (a_addr_pessimistic is None)

    x_next_use = state.next_use['x']
    y_next_use = state.next_use['y']

    # Equivalent runtime addresses (optimistic)
    x_runtime_addr = None if x_addr_optimistic is None else movemanager.b2r(x_addr_optimistic)
    y_runtime_addr = None if y_addr_optimistic is None else movemanager.b2r(y_addr_optimistic)
    x_runtime_load_addr = None if x_load_addr_optimistic is None else movemanager.b2r(x_load_addr_optimistic)
    y_runtime_load_addr = None if y_load_addr_optimistic is None else movemanager.b2r(y_load_addr_optimistic)
    x_runtime_adjust_addr_optimistic = None if x_adjust_addr_optimistic is None else movemanager.b2r(x_adjust_addr_optimistic)
    y_runtime_adjust_addr_optimistic = None if y_adjust_addr_optimistic is None else movemanager.b2r(y_adjust_addr_optimistic)

    x_runtime_next_use = None if x_next_use is None else movemanager.b2r(x_next_use)
    y_runtime_next_use = None if y_next_use is None else movemanager.b2r(y_next_use)

    if a_addr_optimistic is None:
        return

    action_optimistic = memory_binary[a_addr_optimistic] if a_addr_optimistic is not None else -1
    action_pessimistic = memory_binary[a_addr_pessimistic] if a_addr_pessimistic is not None else -1

    if action_pessimistic == 0x00:
        com = "Read OS version number (if X non-zero), or BRK and print OS version (if X=0)"
        if x_addr_pessimistic is not None:
            if memory_binary[x_addr_pessimistic] == 0:
                com = "Execute BRK and print OS version (X=0)"
            else:
                com = "Read OS version number into X"
                auto_comment(x_runtime_next_use,
"""X is the OS version number:
    X=0, OS 1.00 (Early BBC B or Electron OS 1.00)
    X=1, OS 1.20 or American OS
    X=2, OS 2.00 (BBC B+)
    X=3, OS 3.2/3.5 (Master 128)
    X=4, OS 4.0 (Master Econet Terminal)
    X=5, OS 5.0 (Master Compact)""", indent=1)
        auto_comment(runtime_addr, com, align=Align.INLINE, show_blank=True)

    elif action_pessimistic == 0x01:
        com = "Set user flag byte to "
        if x_addr_pessimistic is not None:
            com += str(memory_binary[x_addr_pessimistic])
        else:
            com += "X"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous value of the user flag byte", align=Align.INLINE)

    elif action_pessimistic == 0x02:
        com = "Select input stream X (0=keyboard, 1=RS232, 2=both)"
        if x_addr_pessimistic is not None:
            if memory_binary[x_addr_pessimistic] == 0:
                com = "Select keyboard as input stream with RS232 disabled (X=0)"
            elif memory_binary[x_addr_pessimistic] == 1:
                com = "Select RS232 as input stream with keyboard disabled (X=1)"
            elif memory_binary[x_addr_pessimistic] == 2:
                com = "Select keyboard as input stream with RS232 enabled (X=2)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous input stream (0=keyboard, 1=RS232)", align=Align.INLINE)

    elif action_pessimistic == 0x03:
        com = "Select output stream based on X"
        if x_runtime_addr is not None:
            binary(x_runtime_addr)

        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            com += ": "
            bit_str = ""
            bit_str = append_bit_string(bit_str, x, 0, "enable RS232 output", "disable RS232 output")
            bit_str = append_bit_string(bit_str, x, 1, "disable VDU driver", "enable VDU driver")
            bit_str = append_bit_string(bit_str, x, 2, "disable printer output", "enable printer output")
            bit_str = append_bit_string(bit_str, x, 3, "enable printer despite CTRL-B/C state", "disable printer despite CTRL-B/C state")
            bit_str = append_bit_string(bit_str, x, 4, "disable SPOOLed output", "enable SPOOLed output")
            bit_str = append_bit_string(bit_str, x, 6, "disable printer output unless VDU 1 first", "enable printer output even without VDU 1 first")
            com += bit_str

        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous output stream status byte", align=Align.INLINE)

    elif action_pessimistic == 0x04:
        com = "Enable/disable cursor editing based on X"
        if x_addr_pessimistic is not None:
            if memory_binary[x_addr_pessimistic] == 0:
                com = "Enable cursor editing (X=0)"
            elif memory_binary[x_addr_pessimistic] == 1:
                com = "Disable cursor editing (edit keys give ASCII 135-139) (X=1)"
            elif memory_binary[x_addr_pessimistic] == 2:
                com = "Disable cursor editing (edit keys act as soft keys f11 to f15) (X=2)"
            elif memory_binary[x_addr_pessimistic] == 3:
                com = "Cursor editing keys and COPY simulate a joystick (Master Compact only) (X=3)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use,
"""X is the previous status of the cursor editing keys:
    X=0, cursor editing was enabled (the default setting)
    X=1, cursor editing was disabled, edit keys gave ASCII codes (135 to 139)
    X=2, cursor editing was disabled, edit keys acted as soft keys (11 to 15)
    X=3, cursor editing keys and COPY simulated a joystick (Master Compact only)""", indent=1, show_blank=True)

    elif action_pessimistic == 0x05:
        com = "Select printer destination"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com += ": Ignore printer output (X=0)"
            elif x == 1:
                com += ": Parallel output (X=1)"
            elif x == 2:
                com += ": RS423 output (X=2)"
            elif x == 3:
                com += ": User printer routine (X=3)"
            elif x == 4:
                com += ": Net printer (X=4)"
            else:
                com += ": User printer routine (X>4)"
        else:
            com += " based on X"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use,
"""X is the previous printer destination:
    X=0, printer sink (printer output ignored)
    X=1, parallel output
    X=2, RS423 output (will act as sink if RS423 is enabled using OSBYTE 3)
    X=3, user printer routine
    X=4, net printer
    X=5+, user printer routine""", indent=1, show_blank=True)

    elif action_pessimistic == 0x06:
        com = "Set printer ignore character to "
        if x_addr_pessimistic is not None:
            com += "X=" + str(memory_binary[x_addr_pessimistic])
            if x_runtime_addr is not None:
                char(x_runtime_addr)
        else:
            com += "X"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous printer ignore character", align=Align.INLINE)

    elif (action_optimistic == 0x07) or (action_optimistic == 0x08):
        # Label the operand where X is set (optimistically)
        enum_lookup(x_addr_optimistic, baud_rate_enum, "X=baud rate")

        # Label the actual call and following use pessimistically
        if (action_pessimistic == 0x07) or (action_pessimistic == 0x08):
            if action_pessimistic == 0x07:
                com = "Set serial receive rate "
            else:
                com = "Set serial transmission rate "

            if x_addr_pessimistic is not None:
                x = memory_binary[x_addr_pessimistic]
                if x in baud_rates:
                    com += "to " + baud_rates[x] + " (X=" + str(x) + ")"
                else:
                    com += "based on X"
            else:
                com += "based on X"
            auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            if x_runtime_next_use or y_runtime_next_use:
                next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
                auto_comment(next_use,
    """X and Y contain the previous serial ULA register contents (not Electron).
    Bits 0-2 = transmit rate
    Bits 3-5 = receive rate
    Bit 6    = RS423 in control (if set) / Tape in control (if clear)
    Bit 7    = cassette motor""", indent=1, show_blank=True)

    elif action_pessimistic == 0x09:
        com = "Set 'mark' duration of flashing colours to "
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com += "infinity (X=0)"
            else:
                com += "X=" + utils.count_with_units(x, "vsync (fiftieth of a second)", "vsyncs (fiftieths of a second)")
        else:
            com += "X fiftieths of a second"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous mark duration (in fiftieths of a second)", align=Align.INLINE)

    elif action_pessimistic == 0x0a:
        com = "Set 'space' duration of flashing colours to "
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com += "infinity (X=0)"
            else:
                com += "X=" + utils.count_with_units(x, "vsync (fiftieth of a second)", "vsyncs (fiftieths of a second)")
        else:
            com += "X fiftieths of a second"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous space duration (in fiftieths of a second)", align=Align.INLINE)

    elif action_pessimistic == 0x0b:
        com = "Set keyboard auto-repeat delay"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com = "Disable keyboard auto-repeat (X=0)"
            else:
                com += " to X=" + utils.count_with_units(x, "centisecond", "centiseconds")
        else:
            com += " to X centiseconds"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous keyboard auto-repeat delay (in centiseconds)", align=Align.INLINE)

    elif action_pessimistic == 0x0c:
        com = "Set keyboard auto-repeat interval"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com = "Reset keyboard delay and repeat to default values (X=0)"
            else:
                com += " to X=" + utils.count_with_units(x, "centisecond", "centiseconds")
        else:
            com += " to X centiseconds"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous keyboard auto-repeat interval (in centiseconds)", align=Align.INLINE)

    elif action_optimistic == 0x0d:
        # Label the setting of the X register (optimistically)
        if x_addr_optimistic is not None:
            event_number = memory_binary[x_addr_optimistic]
            enum_lookup(x_addr_optimistic, event_enum, "X=event number")

        # Comment on the line itself (pessimistically)
        com = "Disable event X"
        if x_addr_pessimistic:
            event_number = memory_binary[x_addr_pessimistic]
            if event_number in event_names:
                com = "Disable '" + event_names[event_number] + "' event (X=" + str(event_number) + ")"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous value of the event enable flag (0=disabled, non-zero=enabled)", align=Align.INLINE)

    elif action_optimistic == 0x0e:
        if x_addr_optimistic is not None:
            event_number = memory_binary[x_addr_optimistic]
            enum_lookup(x_addr_optimistic, event_enum, "X=event number")

        if action_pessimistic == 0x0e:
            com = "Enable event X"
            if x_addr_pessimistic is not None:
                event_number = memory_binary[x_addr_pessimistic]
                if event_number in event_names:
                    com = "Enable '" + event_names[event_number] + "' event (X=" + str(event_number) + ")"
            auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous event enable flag (0=disabled, non-zero=enabled)", align=Align.INLINE)

    elif action_pessimistic == 0x0f:
        com = "Flush all buffers (X=0), or just input buffers (X non-zero)"
        if x_addr_pessimistic is not None:
            if memory_binary[x_addr_pessimistic] == 0:
                com = "Flush all buffers (X=0)"
            else:
                com = "Flush input buffers (X non-zero)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x10:
        com = "Select number of ADC channels based on X"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com = "Disable ADC channel sampling (X=0)"
            else:
                com = "Select " + utils.count_with_units(x, "ADC channel", "ADC channels") + " (X=" + str(x) + ")"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous ADC channel 1-4 or zero if disabled", align=Align.INLINE)

    elif action_pessimistic == 0x11:
        com = "Force ADC conversion on channel X"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            com = "Force ADC conversion on channel X=" + str(x)
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x12:
        auto_comment(runtime_addr, "Reset function keys", align=Align.INLINE)

    elif action_pessimistic == 0x13:
        auto_comment(runtime_addr, "Wait for vertical sync", align=Align.INLINE)

    elif action_pessimistic == 0x14:
        com = "Implode or Explode character definition RAM based on X"
        if x_addr_pessimistic is not None:
            exp = memory_binary[x_addr_pessimistic]
            if exp == 0:
                com = "Implode character definition RAM, can redefine characters 128-159 (X=0)"
            elif exp == 1:
                com = "Explode character definition RAM (one extra page), can redefine characters 128-191 (X=1)"
            elif exp == 2:
                com = "Explode character definition RAM (two extra pages), can redefine characters 128-223 (X=2)"
            elif exp == 3:
                com = "Explode character definition RAM (three extra pages), can redefine characters 128-255 (X=3)"
            elif exp == 4:
                com = "Explode character definition RAM (four extra pages), can redefine characters 128-255 and 32-63 (X=4)"
            elif exp == 5:
                com = "Explode character definition RAM (five extra pages), can redefine characters 128-255 and 32-95 (X=5)"
            elif exp == 6:
                com = "Explode character definition RAM (six extra pages), can redefine all characters 32-255 (X=6)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the new OSHWM (high byte)", align=Align.INLINE)

    elif action_optimistic == 0x15:
        # Comment on the setting of X (optimistically)
        if x_addr_optimistic is not None:
            enum_lookup(x_addr_optimistic, buffer_enum, "X=buffer number")

        # Comment on the line itself (pessimistically)
        if action_pessimistic == 0x15:
            com = "Flush specific buffer X"
            if x_addr_pessimistic is not None:
                buffer = memory_binary[x_addr_pessimistic]
                if buffer in buffer_names:
                    com = "Flush " + buffer_names[buffer] + " (X=" + str(buffer) + ")"
                else:
                    com = "Flush unknown buffer (X=" + str(buffer) + ")"
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x16:
        auto_comment(runtime_addr, "Electron and Master: Increment polling semaphore", align=Align.INLINE)

    elif action_pessimistic == 0x17:
        auto_comment(runtime_addr, "Electron and Master: Decrement polling semaphore", align=Align.INLINE)

    elif action_pessimistic == 0x18:
        auto_comment(runtime_addr, "Electron: External sound (with parameter X)", align=Align.INLINE)

    elif action_pessimistic == 0x19:
        com = "Master only: Restore a group of default font definitions based on X"
        if x_addr_pessimistic is not None:
            font_group = memory_binary[x_addr_pessimistic]

            if font_group in font_definitions:
                com = font_definitions[font_group]
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x44:
        auto_comment(runtime_addr, "Master and B+ only: Test for sideways RAM", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "Bits 0-3 of X indicate use of ROM numbers 4-7 as RAM", align=Align.INLINE)

    elif action_pessimistic == 0x45:
        auto_comment(runtime_addr, "Master and B+ only: Get sideways RAM allocation", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "Bits 0-3 of X indicate ROM numbers 4-7 in use for extended addressing", align=Align.INLINE)

    elif action_pessimistic == 0x6B:
        com = "Master, Compact & Electron: "
        if x_addr_pessimistic is not None:
            bus = memory_binary[x_addr_pessimistic]
            if bus == 0:
                com += "Selects the external bus (running at 1MHz on the Electron) (X=0)"
            elif bus == 1:
                com += "Selects the internal bus running at 2MHz (X=1)"
            else:
                com += "Selects the unknown bus X=" + str(bus)
        else:
            com += "Select 1MHz bus (X=0) or cartridge (X=1)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x6C:
        com = "Master only: Select screen memory for direct access"
        if x_addr_pessimistic is not None:
            bank = memory_binary[x_addr_pessimistic]
            if bank == 0:
                com = "Master only: Select main memory for screen memory direct access (X=0)"
            elif bank == 1:
                com = "Master only: Select shadow memory for screen memory direct access (X=1)"
            else:
                com = "Master only: Selects unknown screen memory bank X=" + str(bank)
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x6d:
        auto_comment(runtime_addr, "Master: Make temporary filing system permanent", align=Align.INLINE)

    elif action_pessimistic == 0x70:
        com = "Master: Select main/shadow memory for VDU access"
        if x_addr_pessimistic is not None:
            bank = memory_binary[x_addr_pessimistic]
            if bank == 0:
                com = "Master: Select main memory for MODE 0-7 and shadow memory for MODE 128-135 VDU access (X=0)"
            elif bank == 1:
                com = "Master: Select main memory for VDU access (X=1)"
            elif bank == 2:
                com = "Master: Select shadow memory for VDU access (X=2)"
            else:
                com += "Master: Select unknown screen memory bank for VDU access (X=" + str(bank) + ")"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous VDU access memory setting (0=main or shadow memory according to current mode, 1=main memory, 2=shadow memory)", align=Align.INLINE)

    elif action_pessimistic == 0x71:
        com = "Master: Select main/shadow memory for display"
        if x_addr_pessimistic is not None:
            bank = memory_binary[x_addr_pessimistic]
            if bank == 0:
                com = "Master: Select main memory for display in MODE 0-7 and shadow memory for MODE 128-135 (X=0)"
            elif bank == 1:
                com = "Master: Select main memory for display (X=1)"
            elif bank == 2:
                com = "Master: Select shadow memory for display (X=2)"
            else:
                com = "Master: Select unknown screen memory bank for display (X=" + str(bank) + ")"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous display memory setting (0=main/shadow memory according to current mode, 1=main memory, 2=shadow memory)", align=Align.INLINE)

    elif action_pessimistic == 0x72:
        com = "B+ and Master only: Write shadow memory use (X=0 is always; X non-zero is no shadow memory for MODEs 0-7)"
        if x_addr_pessimistic is not None:
            bank = memory_binary[x_addr_pessimistic]
            if bank == 0:
                com = "B+ and Master only: Select shadow memory always used (X=0)"
            else:
                com = "B+ and Master only: Select shadow memory except for MODEs 0-7 (X non-zero)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous display memory setting (0=main/shadow memory according to current mode, 1=main memory, 2=shadow memory)", align=Align.INLINE)

    elif action_pessimistic == 0x73:
        com = "Electron: Blank (X non-zero) or restore (X=0) palette"
        if x_addr_pessimistic is not None:
            bank = memory_binary[x_addr_pessimistic]
            if bank == 0:
                com = "Electron: Restores the palette (X=0)"
            else:
                com = "Electron: Set palette colours to black (X non-zero)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x74:
        auto_comment(runtime_addr, "Electron only: Reset sound system", align=Align.INLINE)

    elif action_pessimistic == 0x75:
        auto_comment(runtime_addr, "Read VDU status byte", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use,
"""X is VDU status byte:
    bit 0=printer output enabled by a VDU 2
    bit 1=scrolling disabled (cursor editing)
    bit 2=paged scrolling selected
    bit 3=software scrolling selected (text window)
    bit 4=shadow mode selected
    bit 5=text at graphics cursor (VDU 5)
    bit 6=two cursor editing mode
    bit 7=screen disabled via VDU 21""", indent=1, show_blank=True)

    elif action_pessimistic == 0x76:
        auto_comment(runtime_addr, "Reflect keyboard status in keyboard LEDs", align=Align.INLINE)

    elif action_pessimistic == 0x77:
        auto_comment(runtime_addr, "Close any *SPOOL and *EXEC files", align=Align.INLINE)

    elif action_optimistic == 0x78:
        if action_pessimistic == 0x78:
            auto_comment(runtime_addr, "Write current keys pressed (X and Y)", align=Align.INLINE)
        auto_comment(x_runtime_adjust_addr_optimistic, "X=key", align=Align.INLINE)
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=key", align=Align.INLINE)

    elif action_optimistic == 0x79:
        com = "Keyboard scan, or test for a specific key"
        many_key_scan = False
        one_key_scan = ""
        if x_addr_optimistic is not None:
            key = memory_binary[x_addr_optimistic]
            if key >= 0x80:
                inkey_key = (255-key) ^ 0x80
                if inkey_key in inkey_enum:
                    constant(inkey_key, inkey_enum[inkey_key])
                    key_exp = make_eor(make_subtract(255, inkey_enum[inkey_key]), 128)
                    auto_expr(x_runtime_addr, key_exp)
                    auto_comment(x_runtime_addr, "X=internal key number EOR 128", align=Align.INLINE)
                com = "Test for " + key_name(inkey_key) + " key pressed (X=%d)" % key
                one_key_scan = key_name(inkey_key)
            else:
                inkey_key = 255-key
                if inkey_key in inkey_enum:
                    constant(inkey_key, inkey_enum[inkey_key])
                    key_exp = make_subtract(255, inkey_enum[inkey_key])
                    auto_expr(x_runtime_addr, key_exp)
                    auto_comment(x_runtime_addr, "X=internal key number", align=Align.INLINE)

                com = "Keyboard scan starting from " + key_name(inkey_key) + " key (X=%d)" % key
                many_key_scan = True

        if action_pessimistic == 0x79:
            auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            com = "X is either the internal key number (0-127) pressed (for a keyboard scan), or the top bit is the key state (when testing a specific key)"
            if one_key_scan != "":
                com = "X has top bit set if " + one_key_scan + " pressed"
            elif many_key_scan:
                com = "X is the internal key number (0-127) if a key is pressed, or " + config.get_assembler().hex2(0xff) + " otherwise"
            auto_comment(x_runtime_next_use, com, align=Align.INLINE)

    elif action_pessimistic == 0x7a:
        auto_comment(runtime_addr, "Keyboard scan starting from key 16", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            com = "X is key number if key is pressed, or " + config.get_assembler().hex2(0xff) + " otherwise"
            auto_comment(x_runtime_next_use, com, align=Align.INLINE)

    elif action_pessimistic == 0x7b:
        auto_comment(runtime_addr, "Printer driver going dormant", align=Align.INLINE)

    elif action_pessimistic == 0x7c:
        auto_comment(runtime_addr, "Clear escape condition", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            com = "X=" + config.get_assembler().hex2(0xff) + " if there was an ESCAPE condition to clear, or zero otherwise"
            auto_comment(x_runtime_next_use, com, align=Align.INLINE)

    elif action_pessimistic == 0x7d:
        auto_comment(runtime_addr, "Set escape condition", align=Align.INLINE)

    elif action_pessimistic == 0x7e:
        auto_comment(runtime_addr, "Clear escape condition and perform escape effects", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            com = "X=" + config.get_assembler().hex2(0xff) + " if there was an ESCAPE condition to clear, or zero otherwise"
            auto_comment(x_runtime_next_use, com, align=Align.INLINE)

    elif action_optimistic == 0x7f:
        # Comment on setting the X register (optimistically)
        # x_adjust_addr_optimistic = state.optimistic['x'].previous_adjust
        auto_comment(x_runtime_adjust_addr_optimistic, "X=File handle", align=Align.INLINE)

        # Comment on the line itself (pessimistically)
        if action_pessimistic == 0x7f:
            auto_comment(runtime_addr, "Check for EOF in file handle X", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is non-zero if reached end of file, zero otherwise", align=Align.INLINE)

    elif action_pessimistic == 0x80:
        com = "Read buffer status or ADC channel"
        input_buffer = None
        output_buffer = None
        is_last_channel = False
        is_read_last_value = False
        if x_addr_pessimistic is not None:
            x_action = memory_binary[x_addr_pessimistic]
            if x_action == 0:
                com = "Read the channel number last used for an ADC conversion and joystick fire buttons (X=0)"
                is_last_channel = True
            elif x_action < 128:
                com = "Read the ADC conversion value for channel X=%d" % (x_action)
                is_read_last_value = True
            else:
                if (255-x_action) in buffer_names:
                    if x_action >= 254:
                        input_buffer = buffer_names[255-x_action]
                    else:
                        output_buffer = buffer_names[255-x_action]

                if x_action in negative_buffer_actions:
                    com = negative_buffer_actions[x_action]
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            if input_buffer:
                com = "X is the number of characters in " + input_buffer
                auto_comment(x_runtime_next_use, com, align=Align.INLINE)
            elif output_buffer:
                com = "X is the number of spaces remaining in " + output_buffer
                auto_comment(x_runtime_next_use, com, align=Align.INLINE)
        if is_last_channel:
            if x_runtime_next_use:
                com = "X has the joystick fire buttons status in the lower two bits: bit 0=left button, bit 1=right button"
                auto_comment(x_runtime_next_use, com, align=Align.INLINE)
            if y_runtime_next_use:
                com = "Y is the last ADC channel number to complete conversion"
                auto_comment(y_runtime_next_use, com, align=Align.INLINE)

        if is_read_last_value:
            if x_runtime_next_use or y_runtime_next_use:
                next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
                auto_comment(next_use, "X and Y contain the ADC value read (low,high)", align=Align.INLINE)

    elif action_optimistic == 0x81:
        # Comment on setting X
        if y_addr_optimistic is not None:
            if memory_binary[y_addr_optimistic] >= 0x80:
                com = "Read a specific key (or read machine type)"
                if x_addr_optimistic is not None:
                    enum_lookup(x_addr_optimistic, inkey_enum, "X=inkey number")

        com = "Read key within time limit, or read a specific key, or read machine type"
        is_read_machine_type = False
        is_read_ascii_key = False
        is_checking_specific_key_pressed = False
        if y_addr_pessimistic is not None:
            if memory_binary[y_addr_pessimistic] >= 0x80:
                com = "Read a specific key (or read machine type)"
                if x_addr_pessimistic is not None:
                    key = memory_binary[x_addr_pessimistic]
                    if key == 0:
                        com = "Read the machine type"
                        is_read_machine_type = True
                    else:
                        auto_comment(x_runtime_addr, "X=inkey key value", align=Align.INLINE)
                        com = "Is the " + key_name(key) + " key pressed?"
                        is_checking_specific_key_pressed = True
            else:
                com = "Wait for a key press with a time limit"
                is_read_ascii_key = True
                if x_addr_pessimistic is not None and y_addr_pessimistic is not None:
                    com = "Wait for a key press within " + utils.count_with_units(memory_binary[x_addr_pessimistic] + 256*memory_binary[y_addr_pessimistic], "centisecond", "centiseconds")

        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use:
            if is_read_machine_type:
                auto_comment(x_runtime_next_use,
"""X is the machine type:
    X=0, BBC microcomputer OS 0.10
    X=1, Acorn Electron OS 1.00
    X=255, BBC microcomputer OS 1.00 or 1.20
    X=254, BBC microcomputer OS A1.0 (USA)
    X=253, Master 128 OS 3.20 or 3.50
    X=251, BBC B+ OS 2.00
    X=250, Acorn Business Computer OS 1.00 or 2.00
    X=247, Master Econet Terminal OS 4.00
    X=245, Master Compact OS 5.10""", indent=1, show_blank=True)
            elif is_read_ascii_key:
                auto_comment(x_runtime_next_use, "X is the ASCII value of the key pressed (assuming Y=0)")

        if y_runtime_next_use:
            if is_read_ascii_key:
                auto_comment(y_runtime_next_use, "Y is zero if key pressed; " + config.get_assembler().hex2(0xff) + " if no key pressed; " + config.get_assembler().hex2(0x1b) + " if ESCAPE pressed", align=Align.INLINE)

        if is_checking_specific_key_pressed:
            if x_runtime_next_use or y_runtime_next_use:
                next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
                auto_comment(next_use, "X and Y contain " + config.get_assembler().hex2(0xff) + " if the key is pressed", align=Align.INLINE)

    elif action_pessimistic == 0x82:
        auto_comment(runtime_addr, "Read the filing system 'machine high order address'", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use or y_runtime_next_use:
            next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
            auto_comment(next_use, "X and Y contain the machine high order address (low, high)", align=Align.INLINE)

    elif action_pessimistic == 0x83:
        auto_comment(runtime_addr, "Read top of operating system RAM address (OSHWM)", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use or y_runtime_next_use:
            next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
            auto_comment(next_use, "X and Y contain the address of OSHWM (low, high)", align=Align.INLINE)

    elif action_pessimistic == 0x84:
        auto_comment(runtime_addr, "Read top of user memory (HIMEM)", align=Align.INLINE)

        # Post exit:
        if x_runtime_next_use or y_runtime_next_use:
            next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
            auto_comment(next_use, "X and Y contain the address of HIMEM (low, high)", align=Align.INLINE)

    elif action_optimistic == 0x85:
        auto_comment(x_runtime_load_addr, "X=MODE number", align=Align.INLINE)

        if action_pessimistic == 0x85:
            com = "Read top of user memory for a given screen mode X"
            if x_addr_pessimistic is not None:
                mode = memory_binary[x_addr_pessimistic]
                com = "Read top of user memory for screen MODE %d" % (mode)
            auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            if x_runtime_next_use or y_runtime_next_use:
                next_use = min(z for z in [x_runtime_next_use, y_runtime_next_use] if z is not None)
                auto_comment(next_use, "X and Y contain the address (low, high)", align=Align.INLINE)

    elif action_pessimistic == 0x86:
        auto_comment(runtime_addr, "Read input cursor position (Sets X=POS and Y=VPOS)", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the horizontal text position ('POS')", align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y is the vertical text position ('VPOS')", align=Align.INLINE)

    elif action_pessimistic == 0x87:
        auto_comment(runtime_addr, "Read character at the text cursor, and current screen MODE", align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the character at the text cursor", align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y is the current screen MODE (0-7)", align=Align.INLINE)

    elif action_pessimistic == 0x88:
        auto_comment(runtime_addr, "*CODE X,Y", align=Align.INLINE)

    elif action_pessimistic == 0x89:
        com = "Switch cassette motor relay on or off, based on X"
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x == 0:
                com = "Switch cassette motor relay off (X=0)"
            else:
                com = "Switch cassette motor relay on (X non-zero)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0x8a:
        if x_addr_optimistic is not None:
            enum_lookup(x_addr_optimistic, buffer_enum, "X=buffer number")

        if action_pessimistic == 0x8a:
            if y_addr_pessimistic is not None:
                y = str(memory_binary[y_addr_pessimistic]) + " "
            else:
                y = "Y "
            com = "Insert value %sinto buffer" % (y)
            if x_addr_pessimistic is not None:
                x = memory_binary[x_addr_pessimistic]
                if x in buffer_names:
                    com = "Insert value %sinto %s (X=%d)" % (y, buffer_names[x], x)
                else:
                    com = "Insert value %sinto unknown buffer (X=%d)" % (y, x)
            else:
                com += " X"
            com += "; carry is clear if successful"

            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x8b:
        opt = []

        if x_addr_pessimistic is not None:
            x = str(memory_binary[x_addr_pessimistic])
        else:
            x = "X"

        if y_addr_pessimistic is not None:
            y = str(memory_binary[y_addr_pessimistic])
        else:
            y = "Y"
        key = x+","+y
        com = "*OPT " + key
        if key in opt_descriptions:
            com += ": " + opt_descriptions[key]
        elif x == "0":
            com += ": Reset all options for current filing system"
        elif x == "3":
            com += ": if TAPE, set interblock gap to " + utils.count_with_units(y, "tenth of a second", "tenths of a second")
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0x8c:
        if x_runtime_addr is not None:
            decimal(x_runtime_addr)

        if action_pessimistic == 0x8c:
            com = "Select TAPE filing system"
            if x_addr_pessimistic is not None:
                baud = memory_binary[x_addr_pessimistic]
                if baud == 0:
                    com += " at default 1200 baud (X=0)"
                elif baud == 3:
                    com += " at 300 baud (X=3)"
                else:
                    com += " at 1200 baud (X=%d)" % (baud)
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x8d:
        auto_comment(runtime_addr, "Select ROM filing system", align=Align.INLINE)

    elif action_optimistic == 0x8e:
        auto_comment(x_runtime_adjust_addr_optimistic, "X=ROM number", align=Align.INLINE)
        if action_pessimistic == 0x8e:
            auto_comment(runtime_addr, "Enter language ROM X", align=Align.INLINE)

    elif action_pessimistic == 0x8f:
        com = "Issue paged ROM service call"
        if x_addr_pessimistic is not None:
            reason = memory_binary[x_addr_pessimistic]
            if reason in paged_rom_reasons:
                com += ", " + paged_rom_reasons[reason]
            else:
                com += ", Reason X=" + str(reason)
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is zero if a paged ROM claimed the service call", align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y contains a return argument from the ROM service call", align=Align.INLINE)

    elif action_pessimistic == 0x90:
        suffix = ""
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            if x >= 128:
                suffix = "shift display down " + utils.count_with_units(256-x, "line", "lines")
            elif x != 0:
                suffix = "shift display up " + utils.count_with_units(x, "line", "lines")
            x = str(x)
        else:
            x = "X"

        if y_addr_pessimistic is not None:
            y = str(memory_binary[y_addr_pessimistic])
            if len(suffix)>0:
                suffix += ", "
            if y == "0":
                suffix += "turn interlace on"
            else:
                suffix += "turn interlace off"
        else:
            y = "Y"

        if len(suffix)>0:
            suffix = " " + suffix
        com = "*TV " + x + "," + y + suffix
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the previous screen shift setting", align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y is the previous interlace option (0=interlace on, 1=off)", align=Align.INLINE)

    elif action_optimistic == 0x91:
        if x_addr_optimistic is not None:
            enum_lookup(x_addr_optimistic, buffer_enum, "X=buffer number")

        if action_pessimistic == 0x91:
            com = "Get character from input buffer"
            if x_addr_pessimistic is not None:
                enum_lookup(x_addr_pessimistic, buffer_enum, "X=buffer number")
                x = memory_binary[x_addr_pessimistic]
                if x == 0:
                    com = "Get character from keyboard buffer"
                elif x == 1:
                    com = "Get character from RS423 input buffer"
            com += " (C is set if the buffer is empty, otherwise Y=extracted character)"
            auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            auto_comment(y_runtime_next_use, "Y is the character extracted from the buffer", align=Align.INLINE)

    elif (action_pessimistic >= 0x92) and (action_pessimistic <= 0x97):
        com = read_or_write_memory_mapped_device[action_pessimistic]
        if x_addr_pessimistic is not None:
            x = memory_binary[x_addr_pessimistic]
            mmio_address = read_or_write_memory_mapped_address[action_pessimistic] + x
            com += " address " + config.get_assembler().hex4(mmio_address)
        else:
            com += " address " + config.get_assembler().hex4(read_or_write_memory_mapped_address[action_pessimistic]) + " + X"

        is_writing = (action_pessimistic == 0x93) or (action_pessimistic == 0x95) or (action_pessimistic == 0x97)
        # If writing...
        if is_writing:
            if y_addr_pessimistic is not None:
                y = memory_binary[y_addr_pessimistic]
                com += ", value Y=" + str(y)
            else:
                com += ", value Y"
        else:
            com += " into Y"

        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        if not is_writing:
            auto_comment(y_runtime_next_use, "Y is the byte read", align=Align.INLINE)

    elif action_optimistic == 0x98:
        # Comment when setting X register
        if x_addr_optimistic is not None:
            enum_lookup(x_addr_optimistic, buffer_enum, "X=buffer number")

        if action_pessimistic == 0x98:
            com = "Examine status of buffer X"
            if x_addr_pessimistic is not None:
                enum_lookup(x_addr_pessimistic, buffer_enum, "X=buffer number")
                buffer = memory_binary[x_addr_pessimistic]
                if buffer in buffer_names:
                    com = "Examine " + buffer_names[buffer]
                else:
                    com = "Examine status of unknown buffer"
            com += " (exits with carry clear on success)"
            auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            auto_comment(y_runtime_next_use, "Y is: on BBC Micro: offset to next character to be read from address stored at (" + config.get_assembler().hex2(0xFA) + ", "+ config.get_assembler().hex2(0xFB) + "); or Master, B+, Electron: the byte read", align=Align.INLINE)

    elif action_pessimistic == 0x99:
        # Get value to insert if available
        if y_addr_pessimistic is not None:
            ch = "Y=" + str(memory_binary[y_addr_pessimistic])
        else:
            ch = "Y"
        com = "Insert character %s into input buffer X" % ch

        if x_addr_pessimistic is not None:
            buffer = memory_binary[x_addr_pessimistic]
            if buffer == 0:
                com = "Insert character %s into keyboard buffer" % ch
            elif buffer == 1:
                com = "Insert character %s into RS423 input buffer" % ch
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0x9a:
        if x_runtime_addr is not None:
            binary(x_runtime_addr)
        if action_pessimistic == 0x9a:
            com = "Write X to video ULA control register and OS copy (BBC and Master only), and reset flash cycle"
            if x_addr_pessimistic is not None:
                val = memory_binary[x_addr_pessimistic]
                transmit_baud = baud_rates[8 - (val & 7)]
                receive_baud = baud_rates[8 - ((val//8) & 7)]
                rs423_in_charge = (val & 64) != 0
                cassette_motor_on = (val & 128) != 0
                com = "Set cassette motor " + {False: "off", True: "on" }[cassette_motor_on]
                com += ", " + {False: "cassette system in charge", True: "RS423 in charge"}[rs423_in_charge]
                com += ", recieve at " + receive_baud + ", transmit at " + transmit_baud
                com += ", and reset flash cycle"
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x9b:
        com = "Write "
        if x_addr_pessimistic is not None:
            com += str(memory_binary[x_addr_pessimistic]) + " EOR 7 = " + str(memory_binary[x_addr_pessimistic] ^ 7)
        else:
            com += "X EOR 7"
        com += " to video ULA palette register and OS copy (ignored on Electron)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0x9c:
        if x_addr_optimistic is not None:
            binary(x_runtime_addr)
        if action_pessimistic == 0x9c:
            _, write_value = osbyte_rw(x_addr_pessimistic, y_addr_pessimistic)
            com = format_osbyte_rw(x_addr_pessimistic, y_addr_pessimistic, "6850 (ACIA) control register")
            if write_value is not None:
                com += ": "
                com += { 0: "divide counter by 1",
                         1: "divide counter by 16",
                         2: "divide counter by 64 (default for RS423)",
                         3: "master reset",
                         }[write_value & 3]
                com += "; "
                com += { 0: "7 bit word, even parity, 2 stop bits",
                         1: "7 bit word, odd parity, 2 stop bits",
                         2: "7 bit word, even parity, 1 stop bit",
                         3: "7 bit word, odd parity, 1 stop bit",
                         4: "8 bit word, 2 stop bits",
                         5: "8 bit word, 1 stop bit",
                         6: "8 bit word, even parity, 1 stop bit",
                         7: "8 bit word, odd parity, 1 stop bit"
                         }[(write_value // 4) & 7]
                com += "; "
                com += { 0: "RTS low, transmit interrupt disabled",
                         1: "RTS low, transmit interrupt enabled",
                         2: "RTS high, transmit interrupt disabled",
                         3: "RTS low, break level on data output, transmit interrupt disabled"
                         }[(write_value // 32) & 3]
                if (write_value & 128) != 0:
                    com += "; enables the receive data register full, over-run, or DCD transition interrupts."
            auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            auto_comment(x_runtime_next_use, "X is the previous value of the control register", align=Align.INLINE)

    elif action_optimistic == 0x9d:
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=file handle", align=Align.INLINE)

        if action_pessimistic == 0x9d:
            com = "Fast Tube BPUT value "
            if x_addr_pessimistic is not None:
                com += "X=" + str(memory_binary[x_addr_pessimistic])
            else:
                com += "X"
            com += " to file handle Y"
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0x9e:
        com = "Read command/data byte from speech processor"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0x9f:
        auto_comment(y_runtime_adjust_addr_optimistic, "Y=byte to write", align=Align.INLINE)

        if action_pessimistic == 0x9f:
            com = "Write "
            if y_addr_pessimistic is not None:
                com += "Y=" + str(memory_binary[y_addr_pessimistic])
            else:
                com += "byte Y"
            com += " to speech processor"
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0xa0:
        com = "Read VDU variable X"
        var1 = "the VDU variable"
        var2 = "next VDU variable"
        if x_addr_pessimistic is not None:
            by = memory_binary[x_addr_pessimistic]
            if by in vdu_variables:
                var1 = vdu_variables[by]
                com ="Read the " + var1
                if (by+1) in vdu_variables:
                    var2 = vdu_variables[by+1]
            com += " (VDU variable X=" + str(by) + ")"

        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X is the " + var1, align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y is the " + var2, align=Align.INLINE)

    elif action_pessimistic == 0xa1:
        com = "Master and Compact: Read CMOS RAM/EEPROM byte X"
        is_get_size = False
        name_of_byte = ""
        if x_addr_pessimistic is not None:
            by = memory_binary[x_addr_pessimistic]

            if by == 255:
                com = "Compact only: Determine if the EEPROM is 128 or 256 bytes long (X=255)"
                is_get_size = True
            else:
                if by in cmos_ram:
                    name_of_byte = "'" + cmos_ram[by] + "'"
                    com = "Master and Compact: Read the " + name_of_byte + " byte from CMOS RAM/EEPROM (X=" + str(by) + ")"
                else:
                    com += "Master and Compact: Read CMOS RAM/EEPROM byte X=" + str(by)

        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        if y_runtime_next_use:
            if is_get_size:
                auto_comment(y_runtime_next_use, "Y=0 means no EEPROM present; Y=127 means 128 byte EEPROM; Y=255 means 256 byte EEPROM present", align=Align.INLINE)
            else:
                if name_of_byte == "":
                    auto_comment(y_runtime_next_use, "Y is the byte value read from the CMOS RAM/EEPROM", align=Align.INLINE)
                else:
                    auto_comment(y_runtime_next_use, "Y is the %s byte read from the CMOS RAM/EEPROM" % name_of_byte, align=Align.INLINE)

    elif action_pessimistic == 0xa2:
        com = "Master and Compact: Write to CMOS RAM/EEPROM byte X"
        if x_addr_pessimistic is not None:
            by = memory_binary[x_addr_pessimistic]
            if by in cmos_ram:
                name_of_byte = "'" + cmos_ram[by] + "'"
                com = "Master and Compact: Write to the " + name_of_byte + " byte from CMOS RAM/EEPROM (X=" + str(by) + ")"
            else:
                com = "Master and Compact: Write to CMOS RAM/EEPROM byte X=" + str(by)
            # TODO: Decode which byte to read and what it means, NUAG P357
        com += " with value Y"
        if y_addr_pessimistic is not None:
            by = memory_binary[y_addr_pessimistic]
            com += "=" + str(by)

        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0xa3:
        com = "Reserved for application software"
        auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_optimistic == 0xa4:
        auto_comment(x_runtime_addr, "X=Address of ROM format code to check (low byte)", align=Align.INLINE)
        auto_comment(y_runtime_addr, "Y=Address of ROM format code to check (high byte)", align=Align.INLINE)
        if action_pessimistic == 0xa4:
            com = "Check for 6502 code in paged ROM format, where XY is the address to check."
            auto_comment(runtime_addr, com, align=Align.INLINE)

    elif action_pessimistic == 0xa5:
        com = "Read output cursor position (Master only)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

        # Post exit:
        auto_comment(x_runtime_next_use, "X=text cursor 'POS'", align=Align.INLINE)
        auto_comment(y_runtime_next_use, "Y=text cursor 'VPOS'", align=Align.INLINE)

    elif (action_optimistic >= 0xa6) and (action_optimistic <= 0xff):
        write_value = None
        if action_optimistic in os_variable_names:
            _, write_value = osbyte_rw(x_addr_optimistic, y_addr_optimistic)

            name = os_variable_names[action_optimistic]
            next_name = None
            if (action_optimistic + 1) in os_variable_names:
                next_name = os_variable_names[action_optimistic + 1]
            next_next_name = None
            if (action_optimistic + 2) in os_variable_names:
                next_next_name = os_variable_names[action_optimistic + 2]

            # Exceptions
            skip_normal_comment = False
            if (action_pessimistic == 0xc6) or (action_pessimistic == 0xc7):
                if x_runtime_adjust_addr_optimistic is not None:
                    auto_comment(x_runtime_adjust_addr_optimistic, "X=File handle", align=Align.INLINE)

            if action_pessimistic == 0xc8:
                if write_value is not None:
                    if write_value & 1:
                        name = "Disable ESCAPE action, "
                    else:
                        name = "Set normal ESCAPE action, "
                    if (write_value & 0xfe) == 0:
                        name += "set normal BREAK action"
                    else:
                        name += "clear memory on BREAK"
            elif action_pessimistic == 0xc9:
                result = "Enable/Disable keyboard (for Econet)"
                if write_value is not None:
                    if write_value == 0:
                        result = "Enable keyboard (for Econet)"
                    else:
                        result = "Disable keyboard (for Econet)"
                auto_comment(runtime_addr, result, align=Align.INLINE)
                skip_normal_comment = True
            elif action_pessimistic == 0xe5:
                if write_value == 0:
                    name = "Set ESCAPE key status to normal action"
                else:
                    name = "Set ESCAPE key to produce ASCII code " + str(write_value)
                auto_comment(runtime_addr, name, align=Align.INLINE)
                skip_normal_comment = True
            elif action_optimistic == 0xff:
                # If writing the startup byte, show it in binary
                if write_value is not None:
                    if x_runtime_addr is not None:
                        binary(x_runtime_addr)

            if (action_pessimistic >= 0xa6) and (action_pessimistic <= 0xff):
                if not skip_normal_comment:
                    com = format_osbyte_rw(x_addr_pessimistic, y_addr_pessimistic, name)
                    auto_comment(runtime_addr, com, align=Align.INLINE)

            # Post exit:
            # Exit parameters specify low byte for a corresponding high byte.
            if next_name == name + " (high byte)":
                name += " (low byte)"
            if next_name and (next_next_name == next_name + " (high byte)"):
                next_name += " (low byte)"
            if x_runtime_next_use:
                if write_value is None:
                    auto_comment(x_runtime_next_use, "X=value of " + name, align=Align.INLINE)
                else:
                    auto_comment(x_runtime_next_use, "X=old value of " + name, align=Align.INLINE)
            if y_runtime_next_use:
                if next_name:
                    auto_comment(y_runtime_next_use, "Y=value of " + next_name, align=Align.INLINE)

            # Exceptions
            if action_pessimistic == 0xff:
                auto_comment(x_runtime_next_use,
"""X is the startup option byte:
    bits 0 to 2     screen MODE selected following reset
    bit 3           if clear reverse action of SHIFT+BREAK
    bits 4 and 5    used to set disc drive timings (see below)
    bit 6           not used by OS (reserved for future applications)
    bit 7           if clear select NFS, if set select DFS

Disc drive timing links:
|                           |                8271                 |          1770           |          1772           |
|---------------------------|-------------------------------------|-------------------------|-------------------------|
| b5 | b4 | link 3 | link 4 | step time | settle time | head load | step time | settle time | step time | settle time |
|----|----|--------|--------|-----------|-------------|-----------|-----------|-------------|-----------|-------------|
|  0 | 0  | 1      | 1      | 4         | 16          | 0         | 6         | 30          | 6         | 15          |
|  0 | 1  | 1      | 0      | 6         | 16          | 0         | 12        | 30          | 12        | 15          |
|  1 | 0  | 0      | 1      | 6         | 50          | 32        | 20        | 30          | 2         | 15          |
|  1 | 1  | 0      | 0      | 24        | 20          | 64        | 30        | 30          | 3         | 15          |
|---------------------------------------------------------------------------------------------------------------------|""", indent=1, show_blank=True, word_wrap=False)
    elif action_pessimistic in osbyte_extra_descriptions:
        # We don't know much about these, but label them at least
        com = osbyte_extra_descriptions[action_pessimistic] + " (see https://beebwiki.mdfs.net/OSBYTEs)"
        auto_comment(runtime_addr, com, align=Align.INLINE)

def oscli_hook(runtime_addr, state, subroutine):
    x_addr_optimistic = state.optimistic['x'].get_previous_load_imm_operand()
    y_addr_optimistic = state.optimistic['y'].get_previous_load_imm_operand()
    xy_addr(x_addr_optimistic, y_addr_optimistic)

# ENHANCE: Split this up somehow into "tube or host" and "just host"?
def memory_regions():
    """Name the regions of the Acorn machines' memory, to group the list of
    memory locations at the top of the output (see memory_region()). (Called
    by mos_labels(), once per session.)"""
    extras = session.current().extras
    if extras.get("acorn.memory_regions"):
        return
    extras["acorn.memory_regions"] = True

    memory_region(0x0000, 0x0100, "Zero page")
    memory_region(0x0100, 0x0200, "Stack")
    memory_region(0x0200, 0x0236, "OS vectors")
    memory_region(0x0236, 0x0400, "OS workspace")
    memory_region(0x0400, 0x0800, "Language workspace")
    memory_region(0x0800, 0x0e00, "OS workspace")
    memory_region(0x0e00, 0x8000, "User memory")
    memory_region(0x8000, 0xc000, "Paged ROM")
    memory_region(0xc000, 0xfc00, "MOS ROM")
    memory_region(0xfc00, 0xff00, "Hardware")
    memory_region(0xff00, 0xffb3, "MOS ROM")

    # The entry points go from &ffb3 (OSWRSC, on the Master and B+) to &fff9
    # (OSCLI). The 6502's NMI, reset and IRQ vectors follow (a region named
    # by the CPU).
    memory_region(0xffb3, 0xfffa, "MOS entry points")

def mos_labels():
    # (bbc(), electron(), b_plus() and master() all call this)
    register_snippets()
    memory_regions()

    optional_label(0x00f2, "os_text_ptr")
    optional_label(0x00f4, "romsel_copy")
    optional_label(0x00f6, "osrdsc_ptr")

    def ol2(addr, name):
        optional_label(addr    , name)
        optional_label(addr + 1, "%s+1" % name, addr)

    for vector in vectors:
        ol2(vector, vectors[vector])

    optional_label(0xffc2, "gsinit")
    optional_label(0xffc5, "gsread")

    subroutine(0xffb9, "osrdsc", None, None, hook=osrdsc_hook, is_entry_point=False)
    subroutine(0xffbc, "vduchr", None, None, hook=oswrch_hook, is_entry_point=False)
    subroutine(0xffbf, "oseven", None, None, hook=oseven_hook, is_entry_point=False)
    subroutine(0xffce, "osfind", None, None, hook=osfind_hook, is_entry_point=False)
    subroutine(0xffc8, "nvrdch", None, None, hook=osrdch_hook, is_entry_point=False)
    subroutine(0xffcb, "nvwrch", None, None, hook=oswrch_hook, is_entry_point=False)
    subroutine(0xffd1, "osgbpb", None, None, hook=osgbpb_hook, is_entry_point=False)
    subroutine(0xffd4, "osbput", None, None, hook=osbput_hook, is_entry_point=False)
    subroutine(0xffd7, "osbget", None, None, hook=osbget_hook, is_entry_point=False)
    subroutine(0xffda, "osargs", None, None, hook=osargs_hook, is_entry_point=False)
    subroutine(0xffe0, "osrdch", None, None, hook=osrdch_hook, is_entry_point=False)
    subroutine(0xffe3, "osasci", None, None, hook=oswrch_hook, is_entry_point=False)
    subroutine(0xffe7, "osnewl", None, None, hook=osnewl_hook, is_entry_point=False)
    subroutine(0xffec, "oswrcr", None, None, hook=oswrcr_hook, is_entry_point=False)
    subroutine(0xffee, "oswrch", None, None, hook=oswrch_hook, is_entry_point=False)
    subroutine(0xfff4, "osbyte", None, None, hook=osbyte_hook, is_entry_point=False)
    subroutine(0xfff1, "osword", None, None, hook=osword_hook, is_entry_point=False)
    subroutine(0xffdd, "osfile", None, None, hook=osfile_hook, is_entry_point=False)
    subroutine(0xfff7, "oscli",  None, None, hook=oscli_hook,  is_entry_point=False)

def is_sideways_rom():
    auto_comment(0x8000, "Sideways ROM header")
    label(0x8000, "rom_header")
    def check_entry(runtime_addr, entry_type):
        runtime_addr = RuntimeAddr(runtime_addr)
        jmp_abs_opcode = 0x4c
        if memory[runtime_addr] == jmp_abs_opcode:
            label(runtime_addr, entry_type + "_entry")
            entry(runtime_addr)
            label(memorymanager.get_u16_runtime(runtime_addr + 1), entry_type + "_handler")
    check_entry(0x8000, "language")
    check_entry(0x8003, "service")
    label(0x8006, "rom_type")
    label(0x8007, "copyright_offset")
    copyright_offset = memory[0x8007]
    auto_expr(0x8007, "copyright - rom_header - 1")
    label(0x8008, "binary_version")
    label(0x8009, "title")
    version_address = stringz(0x8009, True)
    if version_address < (0x8000 + copyright_offset + 1):
        label(version_address, "version")
    label(0x8000 + copyright_offset + 1, "copyright")

    if not classification.is_classified(0x8000 + copyright_offset + 1):
        stringz(0x8000 + copyright_offset + 1)
    # ENHANCE: We could recognise tube transfer/relocation data in header

def label_tube(base, name):
    optional_label(base + 0, "tube_%s_r1_status" % name, definable_inline=False)
    optional_label(base + 1, "tube_%s_r1_data" % name, definable_inline=False)
    optional_label(base + 2, "tube_%s_r2_status" % name, definable_inline=False)
    optional_label(base + 3, "tube_%s_r2_data" % name, definable_inline=False)
    optional_label(base + 4, "tube_%s_r3_status" % name, definable_inline=False)
    optional_label(base + 5, "tube_%s_r3_data" % name, definable_inline=False)
    optional_label(base + 6, "tube_%s_r4_status" % name, definable_inline=False)
    optional_label(base + 7, "tube_%s_r4_data" % name, definable_inline=False)

def hardware(machine):
    if machine == machinetype.MachineType.MACHINE_6502SP:
        label_tube(0xfef8, "parasite")
        return

    #######################################################################
    # FRED: see p404 of NAUG and https://mdfs.net/Docs/Comp/BBC/Hardware/FREDAddrs
    # Some addresses conflict between different hardware, we make some fairly arbitrary
    # decisions about how to decode these addresses.
    #######################################################################

    optional_label(0xfc00, "fred", definable_inline=False)

    # FC00-03 Byte-Wide Expansion RAM
    #optional_label(0xfc00, "fred_bytewide_expansion_ram_addr_b0_b7", definable_inline=False)
    #optional_label(0xfc01, "fred_bytewide_expansion_ram_addr_b8_b15", definable_inline=False)
    #optional_label(0xfc02, "fred_bytewide_expansion_ram_addr_b16_b23", definable_inline=False)
    #optional_label(0xfc03, "fred_bytewide_expansion_ram_data", definable_inline=False)

    # FC04-05 BeebOPL (FM Synthsiser for the BBC Micro)
    optional_label(0xfc04, "fred_beebopl0", definable_inline=False)
    optional_label(0xfc05, "fred_beebopl1", definable_inline=False)

    # FC08-0F Ample M2000/EMR/EE MIDI Interface (see also FCF0)
    optional_label(0xfc08, "fred_midi_port1_6850_control_or_status", definable_inline=False)
    optional_label(0xfc09, "fred_midi_port1_6850_data", definable_inline=False)
    optional_label(0xfc0a, "fred_midi_port2_6850_control_or_status", definable_inline=False)
    optional_label(0xfc0b, "fred_midi_port2_6850_data", definable_inline=False)
    optional_label(0xfc0c, "fred_midi_port3_6850_control_or_status", definable_inline=False)
    optional_label(0xfc0d, "fred_midi_port3_6850_data", definable_inline=False)
    optional_label(0xfc0e, "fred_output_latch0", definable_inline=False)
    optional_label(0xfc0f, "fred_output_latch1", definable_inline=False)

    # FC10-13 Teletext Hardware
    for i in range(0,4):
        optional_label(0xfc10+i, "fred_teletext_{0}".format(i), definable_inline=False)

    # FC14-1F Prestel Hardware
    for i in range(0,8):
        optional_label(0xfc14+i, "fred_prestel_{0}".format(i), definable_inline=False)

    # FC1C-FC1F Teletext display expansion
    optional_label(0xfc1c, "fred_jafa_6845_write_addr".format(i), definable_inline=False)
    optional_label(0xfc1d, "fred_jafa_6845_write_data".format(i), definable_inline=False)
    optional_label(0xfc1e, "fred_jafa_6845_read_status".format(i), definable_inline=False)
    optional_label(0xfc1f, "fred_jafa_6845_read_data".format(i), definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FC28-2F Electron Econet
        optional_label(0xFC28, "electron_econet_fc28", definable_inline=False)
        optional_label(0xFC29, "electron_econet_fc29", definable_inline=False)
        optional_label(0xFC2A, "electron_econet_fc2a", definable_inline=False)
        optional_label(0xFC2B, "electron_econet_fc2b", definable_inline=False)
        optional_label(0xFC2C, "electron_econet_fc2c", definable_inline=False)
        optional_label(0xFC2D, "electron_econet_fc2d", definable_inline=False)
        optional_label(0xFC2E, "electron_econet_fc2e", definable_inline=False)
        optional_label(0xFC2F, "electron_econet_fc2f", definable_inline=False)
    else:
        # FC20-3F SID Interface (6581 Sound Interface Device)
        optional_label(0xfc20, "sid_voice1_frequency_low", definable_inline=False)
        optional_label(0xfc21, "sid_voice1_frequency_high", definable_inline=False)
        optional_label(0xfc22, "sid_voice1_pw_low", definable_inline=False)
        optional_label(0xfc23, "sid_voice1_pw_high", definable_inline=False)
        optional_label(0xfc24, "sid_voice1_control_register", definable_inline=False)
        optional_label(0xfc25, "sid_voice1_attack_slash_decay", definable_inline=False)
        optional_label(0xfc26, "sid_voice1_sustain_slash_release", definable_inline=False)

        optional_label(0xfc27, "sid_voice2_frequency_low", definable_inline=False)
        optional_label(0xfc28, "sid_voice2_frequency_high", definable_inline=False)
        optional_label(0xfc29, "sid_voice2_pw_low", definable_inline=False)
        optional_label(0xfc2a, "sid_voice2_pw_high", definable_inline=False)
        optional_label(0xfc2b, "sid_voice2_control_register", definable_inline=False)
        optional_label(0xfc2c, "sid_voice2_attack_slash_decay", definable_inline=False)
        optional_label(0xfc2d, "sid_voice2_sustain_slash_release", definable_inline=False)

        optional_label(0xfc2e, "sid_voice3_frequency_low", definable_inline=False)
        optional_label(0xfc2f, "sid_voice3_frequency_high", definable_inline=False)
        optional_label(0xfc30, "sid_voice3_pw_low", definable_inline=False)
        optional_label(0xfc31, "sid_voice3_pw_high", definable_inline=False)
        optional_label(0xfc32, "sid_voice3_control_register", definable_inline=False)
        optional_label(0xfc33, "sid_voice3_attack_slash_decay", definable_inline=False)
        optional_label(0xfc34, "sid_voice3_sustain_slash_release", definable_inline=False)

        optional_label(0xfc35, "sid_filter_fc_low", definable_inline=False)
        optional_label(0xfc36, "sid_filter_fc_high", definable_inline=False)
        optional_label(0xfc37, "sid_filter_reset_slash_filter", definable_inline=False)
        optional_label(0xfc38, "sid_filter_mode_slash_volume", definable_inline=False)

        optional_label(0xfc39, "sid_potx", definable_inline=False)
        optional_label(0xfc3a, "sid_poty", definable_inline=False)
        optional_label(0xfc3b, "sid_osc3_slash_random", definable_inline=False)
        optional_label(0xfc3c, "sid_env3", definable_inline=False)

    # FC20-27 IEEE Interface (TMS 9914A)
    #for i in range(0,8):
    #    optional_label(0xfc20+i, "fred_IEE488_{0}".format(i), definable_inline=False)

    # FC30-3F Cambridge Ring interface
    #for i in range(0,16):
    #    optional_label(0xfc30+i, "fred_cambridge_ring_{0}".format(i), definable_inline=False)

    # FC30-3F WiFi interface 16C2552 UART
    #optional_label(0xfc30, "wifi_data", definable_inline=False)
    #optional_label(0xfc31, "wifi_interrupt_enable", definable_inline=False)
    #optional_label(0xfc32, "wifi_fifo_control_or_interrupt_id", definable_inline=False)
    #optional_label(0xfc33, "wifi_line_control", definable_inline=False)
    #optional_label(0xfc34, "wifi_modem_control", definable_inline=False)
    #optional_label(0xfc35, "wifi_line_status", definable_inline=False)
    #optional_label(0xfc36, "wifi_modem_status", definable_inline=False)
    #optional_label(0xfc37, "wifi_scratchpad", definable_inline=False)

    # FC40-4F Hard Drive Access
    for i in range(0,16):
        optional_label(0xfc40+i, "fred_hard_drive_{0}".format(i), definable_inline=False)
    for i in range(0,16):
        optional_label(0xfc50+i, "fred_undefinedA_{0}".format(i), definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FC60-6F Electron Serial controller (2681 ACIA Serial controller)
        optional_label(0xfc60, "electron_serial_mode_register_A", definable_inline=False)
        optional_label(0xfc61, "electron_serial_clock_select_A_or_status_register_A", definable_inline=False)
        optional_label(0xfc62, "electron_serial_command_register_A", definable_inline=False)
        optional_label(0xfc63, "electron_serial_data_A", definable_inline=False)
        optional_label(0xfc64, "electron_serial_aux_control_or_input_port_changed", definable_inline=False)
        optional_label(0xfc65, "electron_serial_interupt_mask_or_status", definable_inline=False)
        optional_label(0xfc66, "electron_serial_counter_or_timer_upper_register", definable_inline=False)
        optional_label(0xfc67, "electron_serial_counter_or_timer_lower_register", definable_inline=False)
        optional_label(0xfc68, "electron_serial_mode_register_B", definable_inline=False)
        optional_label(0xfc69, "electron_serial_clock_select_B_or_status_register_B", definable_inline=False)
        optional_label(0xfc6A, "electron_serial_command_register_B", definable_inline=False)
        optional_label(0xfc6B, "electron_serial_data_B", definable_inline=False)
        optional_label(0xfc6C, "electron_serial_reserved", definable_inline=False)
        optional_label(0xfc6D, "electron_serial_io_port_data", definable_inline=False)
        optional_label(0xfc6E, "electron_serial_set_output_port_bits_or_start_counter", definable_inline=False)
        optional_label(0xfc6F, "electron_serial_reset_output_port_bits_or_stop_counter", definable_inline=False)

        # FC70-73 Electron Plus 1 expansion
        optional_label(0xfc70, "electron_expansion_atod_convertor_control_or_data")
        optional_label(0xfc71, "electron_expansion_centronics_parallel_data")
        optional_label(0xfc72, "electron_expansion_status")
        optional_label(0xfc73, "electron_expansion_romstrobe")
        optional_label(0xfc78, "electron_laserdisc_0")
        optional_label(0xfc79, "electron_laserdisc_1")
        optional_label(0xfc7a, "electron_laserdisc_2")
        optional_label(0xfc7b, "electron_laserdisc_3")
        optional_label(0xfc7c, "electron_laserdisc_4")
        optional_label(0xfc7d, "electron_laserdisc_5")
        optional_label(0xfc7e, "electron_laserdisc_6")
        #optional_label(0xfc7f, "electron_laserdisc_7")
        optional_label(0xfc7f, "electron_shadow_ram_paging_register", definable_inline=False)
    else:
        # FC60-6F Additional/External Serial ports
        optional_label(0xfc60, "fred_port1_6850_control_or_status", definable_inline=False)
        optional_label(0xfc61, "fred_port1_6850_data", definable_inline=False)
        optional_label(0xfc62, "fred_port1_baud_rate_control", definable_inline=False)
        optional_label(0xfc64, "fred_port2_6850_control_or_status", definable_inline=False)
        optional_label(0xfc65, "fred_port2_6850_data", definable_inline=False)
        optional_label(0xfc66, "fred_port2_baud_rate_control", definable_inline=False)
        optional_label(0xfc68, "fred_port3_6850_control_or_status", definable_inline=False)
        optional_label(0xfc69, "fred_port3_6850_data", definable_inline=False)
        optional_label(0xfc6a, "fred_port3_baud_rate_control", definable_inline=False)
        optional_label(0xfc6c, "fred_port4_6850_control_or_status", definable_inline=False)
        optional_label(0xfc6d, "fred_port4_6850_data", definable_inline=False)
        optional_label(0xfc6e, "fred_port4_baud_rate_control", definable_inline=False)

        # FC7C-7F Watford Video Digitiser
        optional_label(0xfc7c, "fred_6821_register_0", definable_inline=False)
        optional_label(0xfc7d, "fred_6821_register_1", definable_inline=False)
        optional_label(0xfc7e, "fred_6821_register_2", definable_inline=False)
        optional_label(0xfc7f, "fred_6821_register_3", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        #FC84-85 Electron external sound
        optional_label(0xfc84, "external_sound_support_0", definable_inline=False)
        optional_label(0xfc85, "external_sound_support_1", definable_inline=False)
    else:
        # FC80-87 LCD Display Control
        for i in range(0,4):
            optional_label(0xfc80+2*i, "fred_lcd_bank{0}_display_control_or_status".format(i), definable_inline=False)
            optional_label(0xfc81+2*i, "fred_lcd_bank{0}_display_data".format(i), definable_inline=False)

    # FC88-8B HostFS+TubeTCP
    optional_label(0xfc88, "hostfs_and_tube_tcp0", definable_inline=False)
    optional_label(0xfc89, "hostfs_and_tube_tcp1", definable_inline=False)
    optional_label(0xfc8A, "hostfs_and_tube_tcp2", definable_inline=False)
    optional_label(0xfc8B, "hostfs_and_tube_tcp3", definable_inline=False)
    optional_label(0xfc8C, "hostfs_and_tube_tcp4", definable_inline=False)
    optional_label(0xfc8D, "hostfs_and_tube_tcp5", definable_inline=False)
    optional_label(0xfc8E, "hostfs_and_tube_tcp6", definable_inline=False)
    optional_label(0xfc8F, "hostfs_and_tube_tcp7", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FC90-9F Electron sound and speech cartridge
        for i in range(0,16):
            optional_label(0xfc90+i, "electron_sound_and_speech_{0}".format(i), definable_inline=False)
    else:
        # FC90-9F CTS Recognition Plus palette expander additional 6522 VIA
        optional_label(0xfc90, "cts_palette_io_register_B", definable_inline=False)
        optional_label(0xfc91, "cts_palette_io_register_A", definable_inline=False)
        optional_label(0xfc92, "cts_palette_ddr_B", definable_inline=False)
        optional_label(0xfc93, "cts_palette_ddr_A", definable_inline=False)
        optional_label(0xfc94, "cts_palette_T1_low_order_counter_or_latches", definable_inline=False)
        optional_label(0xfc95, "cts_palette_T1_high_order_counter", definable_inline=False)
        optional_label(0xfc96, "cts_palette_T1_low_order_latches", definable_inline=False)
        optional_label(0xfc97, "cts_palette_T1_high_order_latches", definable_inline=False)
        optional_label(0xfc98, "cts_palette_T2_low_order_counter_or_latches", definable_inline=False)
        optional_label(0xfc99, "cts_palette_T2_high_order_counter", definable_inline=False)
        optional_label(0xfc9a, "cts_palette_shift_register", definable_inline=False)
        optional_label(0xfc9b, "cts_palette_auxilary_control_register", definable_inline=False)
        optional_label(0xfc9c, "cts_palette_peripheral_control_register", definable_inline=False)
        optional_label(0xfc9d, "cts_palette_interrupt_flag_register", definable_inline=False)
        optional_label(0xfc9e, "cts_palette_interrupt_enable_register", definable_inline=False)
        optional_label(0xfc9f, "cts_palette_io_register_A_no_handshake", definable_inline=False)

    # FCA0-B7 CTS Recognition Plus palette expander
    #for i in range(0,24):
    #    optional_label(0xfca0+i, "fred_cts_{0}_colour_{1}".format(["red","green","blue"][i // 8], i & 7), definable_inline=False)

    # FCB0-BF PRISMA video system
    optional_label(0xfcb0, "prisma_reserved", definable_inline=False)
    optional_label(0xfcb1, "prisma_horizontal_line_phase", definable_inline=False)
    optional_label(0xfcb2, "prisma_frame_grab_black_level_and_gain", definable_inline=False)
    optional_label(0xfcb3, "prisma_frame_grab_and_control_output_register", definable_inline=False)
    optional_label(0xfcb4, "prisma_palette_control", definable_inline=False)
    optional_label(0xfcb5, "prisma_palette_address", definable_inline=False)
    optional_label(0xfcb6, "prisma_window_or_background_delay_trims", definable_inline=False)
    optional_label(0xfcb7, "prisma_overlay_or_NVM_page_paged_into_JIM_at_FDxx", definable_inline=False)
    optional_label(0xfcb8, "prisma_HD63484_ACRTC_address_or_status", definable_inline=False)
    optional_label(0xfcb9, "prisma_HD63484_ACRTC_data", definable_inline=False)
    optional_label(0xfcba, "prisma_control_or_status", definable_inline=False)
    optional_label(0xfcbb, "prisma_palette_data", definable_inline=False)
    optional_label(0xfcbc, "prisma_overlay_data", definable_inline=False)
    optional_label(0xfcbd, "prisma_overlay_address_or_ACRTC_data_read", definable_inline=False)
    optional_label(0xfcbe, "prisma_NVR_data", definable_inline=False)
    optional_label(0xfcbf, "prisma_reserved_for_control_in_multiple_PRISMA_systems", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FCC0    Electron digital joystick option C (see also FCD0)
        # optional_label(0xfcc0, "electron_joystickC_state", definable_inline=False)

        # FCC0-C7 Electron 1770 floppy disk expansion (Plus 3)
        optional_label(0xfcc0, "electron_1770_control_port", definable_inline=False)
        optional_label(0xfcc4, "electron_1770_command_or_status_register", definable_inline=False)
        optional_label(0xfcc5, "electron_1770_track_register", definable_inline=False)
        optional_label(0xfcc6, "electron_1770_sector_register", definable_inline=False)
        optional_label(0xfcc7, "electron_1770_data_register", definable_inline=False)

    # FCCC-CF Morley Electronics RAMdisc - paged into JIM at &FDxx
    optional_label(0xfccc, "morley_ramdisc_bank_select_b8_b15", definable_inline=False)
    optional_label(0xfccd, "morley_ramdisc_bank_select_b16_b23", definable_inline=False)
    optional_label(0xfcce, "morley_ramdisc_bank_select_b24_b31", definable_inline=False)
    optional_label(0xfccf, "morley_ramdisc_control_register", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FCD0    Electron digital joystick option D
        optional_label(0xfcd0, "electron_digital_joystickD_state", definable_inline=False)
        optional_label(0xfcd6, "electron_ii2c_control", definable_inline=False)

    # FCD8-DF PRES Advanced Battery-Backed RAM
    optional_label(0xfcd8, "pres_battery_backed_ram_unlock_AP7_lower_bank", definable_inline=False)
    optional_label(0xfcd9, "pres_battery_backed_ram_lock_AP7_lower_bank", definable_inline=False)
    optional_label(0xfcda, "pres_battery_backed_ram_unlock_AP7_upper_bank", definable_inline=False)
    optional_label(0xfcdb, "pres_battery_backed_ram_lock_AP7_upper_bank", definable_inline=False)
    optional_label(0xfcdc, "pres_battery_backed_ram_unlock_ABR_RAM_bank_0_and_2", definable_inline=False)
    optional_label(0xfcdd, "pres_battery_backed_ram_lock_ABR_RAM_bank_0_and_2", definable_inline=False)
    optional_label(0xfcde, "pres_battery_backed_ram_unlock_ABR_RAM_bank_1_and_3", definable_inline=False)
    optional_label(0xfcdf, "pres_battery_backed_ram_lock_ABR_RAM_bank_1_and_3", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FCE0    Electron digital joystick option E
        # optional_label(0xfce0, "electron_digital_joystickE_state", definable_inline=False)

        # FCE0-EF Electron Tube control
        optional_label(0xfce0, "electron_tube_setup_or_status_register", definable_inline=False)
        optional_label(0xfce1, "electron_tube_vdu_transfer_port", definable_inline=False)
        optional_label(0xfce2, "electron_tube_command_status_register", definable_inline=False)
        optional_label(0xfce3, "electron_tube_command_transfer_port", definable_inline=False)
        optional_label(0xfce4, "electron_tube_data_status_register", definable_inline=False)
        optional_label(0xfce5, "electron_tube_data_transfer_port", definable_inline=False)
        optional_label(0xfce6, "electron_tube_interrupt_status_register_slash_CPU", definable_inline=False)
        optional_label(0xfce7, "electron_tube_interrupt_transfer_port", definable_inline=False)
    else:
        # FCE0-EF Watford hand scanner
        optional_label(0xfce0, "watford_hand_scanner_data_byte", definable_inline=False)
        optional_label(0xfce1, "watford_hand_scanner_data_ready", definable_inline=False)
        optional_label(0xfce2, "watford_hand_scanner_start_of_line", definable_inline=False)
        optional_label(0xfce3, "watford_hand_scanner_vertical_pulse", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FCF0    Electron digital joystick option F
        optional_label(0xfcf0, "electron_digital_joystickF_state", definable_inline=False)
    else:
        # FCF0-F7 JGH/ETI/EE/EMR MIDI Interface (see also FC08)
        optional_label(0xfcf0, "fred_MIDI_port_1_6850_control_or_status", definable_inline=False)
        optional_label(0xfcf1, "fred_MIDI_port_1_6850_data", definable_inline=False)
        optional_label(0xfcf2, "fred_MIDI_port_2_6850_control_or_status", definable_inline=False)
        optional_label(0xfcf3, "fred_MIDI_port_2_6850_data", definable_inline=False)
        optional_label(0xfcf4, "fred_MIDI_port_3_6850_control_or_status", definable_inline=False)
        optional_label(0xfcf5, "fred_MIDI_port_3_6850_data", definable_inline=False)
        optional_label(0xfcf6, "fred_MIDI_port_4_6850_control_or_status", definable_inline=False)
        optional_label(0xfcf7, "fred_MIDI_port_4_6850_data", definable_inline=False)

    # FCF8-F9 USB Port
    #optional_label(0xfcf8, "fred_USB_data", definable_inline=False)
    #optional_label(0xfcf9, "fred_USB_control_or_status", definable_inline=False)

    # FCFA-FD DataCentre non-volatile RAM control
    optional_label(0xfcf8, "datacentre_vnc_data_port", definable_inline=False)
    optional_label(0xfcf9, "datacentre_vnc_control_port", definable_inline=False)
    optional_label(0xfcfa, "datacentre_nvram_data", definable_inline=False)
    optional_label(0xfcfb, "datacentre_nvram_data_direction_register", definable_inline=False)

    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        # FCFC-FF Electron Advanced Quarter Meg RAM ('AQR')
        optional_label(0xfcfc, "electron_aqr_ram_bank_select", definable_inline=False)
        optional_label(0xfcfd, "electron_aqr_ram_disable_write_protect", definable_inline=False)
        optional_label(0xfcfe, "electron_aqr_ram_write_protect", definable_inline=False)
    else:
        # FCFC-FF Page-Wide Expansion RAM
        optional_label(0xfcfc, "page_ram_bank_select_b32_b39", definable_inline=False)
        optional_label(0xfcfd, "page_ram_bank_select_b24_b31", definable_inline=False)
        optional_label(0xfcfe, "page_ram_bank_select_b16_b23", definable_inline=False)
        optional_label(0xfcff, "page_ram_bank_select_b8_b15", definable_inline=False)

    #######################################################################
    # JIM, see https://mdfs.net/Docs/Comp/BBC/Hardware/JIMAddrs
    #######################################################################
    optional_label(0xfd00, "jim", definable_inline=False)

    # FDF0-F7 Torch SASI/SCSI Hard Drive Access
    optional_label(0xfdf0, "torch_sasi_slash_scsi_data")
    optional_label(0xfdf1, "torch_sasi_slash_scsi_status_or_reset")
    optional_label(0xfdf2, "torch_sasi_slash_scsi_set_ack_or_select_1")
    optional_label(0xfdf3, "torch_sasi_slash_scsi_select_0")

    optional_label(0xfdfe, "jim_reset_address_low", definable_inline=False)
    optional_label(0xfdff, "jim_reset_address_high", definable_inline=False)

    #######################################################################
    # SHEILA, see https://mdfs.net/Docs/Comp/BBC/Hardware/SHEILAddrs
    #######################################################################
    if machine == machinetype.MachineType.MACHINE_ELECTRON:
        optional_label(0xfe00, "electron_interrupt_control_or_status", definable_inline=False)
        optional_label(0xfe02, "electron_screen_start_div2_low", definable_inline=False)
        optional_label(0xfe03, "electron_screen_start_div2_high", definable_inline=False)
        optional_label(0xfe04, "electron_cassette_data_shift_io", definable_inline=False)
        optional_label(0xfe05, "electron_romsel_and_interrupt_clear", definable_inline=False)
        optional_label(0xfe06, "electron_counter_plus_cassette_control", definable_inline=False)
        optional_label(0xfe07, "electron_cassette_and_mode_and_sound_and_caps_led", definable_inline=False)
        optional_label(0xfe08, "electron_palette_0", definable_inline=False)
        optional_label(0xfe09, "electron_palette_1", definable_inline=False)
        optional_label(0xfe0a, "electron_palette_2", definable_inline=False)
        optional_label(0xfe0b, "electron_palette_3", definable_inline=False)
        optional_label(0xfe0c, "electron_palette_4", definable_inline=False)
        optional_label(0xfe0d, "electron_palette_5", definable_inline=False)
        optional_label(0xfe0e, "electron_palette_6", definable_inline=False)
        optional_label(0xfe0f, "electron_palette_7", definable_inline=False)
    else:
        optional_label(0xfe00, "crtc_address_register", definable_inline=False)
        session.current().trace.substitute_constant_list.append(cpu6502.SubConst("sta crtc_address_register", 'a', crtc_registers_enum, True))
        session.current().trace.substitute_constant_list.append(cpu6502.SubConst("stx crtc_address_register", 'x', crtc_registers_enum, True))
        session.current().trace.substitute_constant_list.append(cpu6502.SubConst("sty crtc_address_register", 'y', crtc_registers_enum, True))

        optional_label(0xfe01, "crtc_register_data", definable_inline=False)

        # FE08-0F 6850 ACIA Serial controller
        optional_label(0xfe08, "acia_control_or_status", definable_inline=False)
        optional_label(0xfe09, "acia_data", definable_inline=False)

        optional_label(0xfe10, "serial_ula_set_baud_cassette_and_motor", definable_inline=False)

        if (machine == machinetype.MachineType.MACHINE_BBC) or (machine == machinetype.MachineType.MACHINE_BPLUS):
            # FE18-1F Station ID/NMI Control (BBC B, B+)
            optional_label(0xfe18, "station_id_disable_net_nmis",  definable_inline=False)
        elif machine == machinetype.MachineType.MACHINE_MASTER:
            # FE18-1F Analogue-to-Digital Convertor (Master)
            optional_label(0xfe18, "a2d_start_conversion_or_read_status",  definable_inline=False)
            optional_label(0xfe19, "a2d_read_data_high_byte",  definable_inline=False)
            optional_label(0xfe1a, "a2d_read_data_low_byte",  definable_inline=False)

        # FE20-2F Video ULA
        optional_label(0xfe20, "video_ula_control", definable_inline=False)
        optional_label(0xfe21, "video_ula_palette", definable_inline=False)
        optional_label(0xfe22, "video_ula_border_colour_and_palette_control", definable_inline=False)
        optional_label(0xfe23, "video_ula_palette_selection", definable_inline=False)

        if machine == machinetype.MachineType.MACHINE_MASTER:
            # FE24-27 Disk control (Master)
            optional_label(0xfe24, "disk_drive_control_register", definable_inline=False)

            # FE28-2B 1770 Floppy Disk Controller (Master)
            optional_label(0xfe28, "fdc_command_or_status", definable_inline=False)
            optional_label(0xfe29, "fdc_track", definable_inline=False)
            optional_label(0xfe2a, "fdc_sector", definable_inline=False)
            optional_label(0xfe2b, "fdc_data", definable_inline=False)

        optional_label(0xfe30, "romsel", definable_inline=False)

        if (machine == machinetype.MachineType.MACHINE_BPLUS) or (machine == machinetype.MachineType.MACHINE_MASTER):
            optional_label(0xfe34, "acccon", definable_inline=False)

        if machine == machinetype.MachineType.MACHINE_MASTER:
            optional_label(0xfe38, "disable_network_nmis", definable_inline=False)
            optional_label(0xfe3c, "enable_network_nmis", definable_inline=False)


        def label_via(base, name):
            optional_label(base +  0, name + "_via_register_b", definable_inline=False)
            optional_label(base +  1, name + "_via_register_a", definable_inline=False)
            optional_label(base +  2, name + "_via_ddrb", definable_inline=False)
            optional_label(base +  3, name + "_via_ddra", definable_inline=False)
            optional_label(base +  4, name + "_via_t1c_l", definable_inline=False)
            optional_label(base +  5, name + "_via_t1c_h", definable_inline=False)
            optional_label(base +  6, name + "_via_t1l_l", definable_inline=False)
            optional_label(base +  7, name + "_via_t1l_h", definable_inline=False)
            optional_label(base +  8, name + "_via_t2c_l", definable_inline=False)
            optional_label(base +  9, name + "_via_t2c_h", definable_inline=False)
            optional_label(base + 10, name + "_via_sr", definable_inline=False)
            optional_label(base + 11, name + "_via_acr", definable_inline=False)
            optional_label(base + 12, name + "_via_pcr", definable_inline=False)
            optional_label(base + 13, name + "_via_ifr", definable_inline=False)
            optional_label(base + 14, name + "_via_ier", definable_inline=False)
            optional_label(base + 15, name + "_via_register_a_no_handshake", definable_inline=False)
        label_via(0xfe40, "system")
        label_via(0xfe60, "user")

        if (machine == machinetype.MachineType.MACHINE_BBC) or (machine == machinetype.MachineType.MACHINE_BPLUS):
            # FE80-9F 8271 Floppy disk controller (BBC B, B+)
            # FE80-9F 1770 Floppy disk controller (BBC B, B+)
            optional_label(0xfe80, "fdc_8271_command_or_status_or_1770_drive_control", definable_inline=False)
            optional_label(0xfe81, "fdc_8271_parameter_or_result", definable_inline=False)
            optional_label(0xfe82, "fdc_8271_reset", definable_inline=False)
            optional_label(0xfe84, "fdc_8271_data_or_1770_command_or_status", definable_inline=False)

            optional_label(0xfe85, "fdc_1770_track", definable_inline=False)
            optional_label(0xfe86, "fdc_1770_sector", definable_inline=False)
            optional_label(0xfe87, "fdc_1770_data", definable_inline=False)

        if machine == machinetype.MachineType.MACHINE_MASTER:
            # FE80-9F Master internal expansion port (PL12)
            for i in range(0,16):
                optional_label(0xfe80+i, "internal_expansion_port_{0}".format(i), definable_inline=False)

            # FE80-8F Videodisc SCSI controller (Master)
            #optional_label(0xfe80, "videodisc_data", definable_inline=False)
            #optional_label(0xfe81, "videodisc_status", definable_inline=False)
            #optional_label(0xfe82, "videodisc_select", definable_inline=False)
            #optional_label(0xfe83, "videodisc_int_enable", definable_inline=False)

        # FEA0-BF 6854 ALDC Econet controller
        optional_label(0xfea0, "econet_control1_or_status1", definable_inline=False)
        optional_label(0xfea1, "econet_control23_or_status2", definable_inline=False)
        optional_label(0xfea2, "econet_data_continue_frame", definable_inline=False)
        optional_label(0xfea3, "econet_data_terminate_frame", definable_inline=False)

        if (machine == machinetype.MachineType.MACHINE_BBC) or (machine == machinetype.MachineType.MACHINE_BPLUS):
            # FEC0-DF Analogue-to-digital convertor (B/B+)
            optional_label(0xfec0, "adc_start_conversion_or_status", definable_inline=False)
            optional_label(0xfec1, "adc_read_data_high_byte", definable_inline=False)
            optional_label(0xfec2, "adc_read_data_low_byte", definable_inline=False)

        if machine == machinetype.MachineType.MACHINE_MASTER:
            # FEC0-DF "Network interface" (Master)
            for i in range(0, 32):
                optional_label(0xfec0+i, "network_interface_{0}".format(i))

            # FEDF    Eureka memory control
            #optional_label(0xfedf, "eureka_memory_control", definable_inline=False)

        # FEE0-FF Tube control
        optional_label(0xfee0, "tube_status_1_and_tube_control", definable_inline=False)
        optional_label(0xfee1, "tube_data_register_1", definable_inline=False)
        optional_label(0xfee2, "tube_status_register_2", definable_inline=False)
        optional_label(0xfee3, "tube_data_register_2", definable_inline=False)
        optional_label(0xfee4, "tube_status_register_3", definable_inline=False)
        optional_label(0xfee5, "tube_data_register_3", definable_inline=False)
        optional_label(0xfee6, "tube_status_register_4_and_cpu_control", definable_inline=False)
        optional_label(0xfee7, "tube_data_register_4", definable_inline=False)

        # Torch Tube control
        # FEE0-EF 6522 VIA access to Torch 8255, release Torch reset line
        #optional_label(0xfee0, "torch_tube_data_out_from_host", definable_inline=False)
        #optional_label(0xfee1, "torch_tube_data_in_to_host", definable_inline=False)
        #optional_label(0xfeed, "torch_tube_status", definable_inline=False)
        #for i in range(0,16):
        #    optional_label(0xfef0+i, "torch_tube_via_access_{0}_assert_reset_line".format(i))

        # CUBE Tube control (may also be mirrored at &FEE0)
        # FEF0-FF 6522 VIA access to CUBE 8255
        optional_label(0xfef0, "cube_tube_data_out_from_host", definable_inline=False)
        optional_label(0xfef1, "cube_tube_data_in_to_host", definable_inline=False)
        optional_label(0xfefd, "cube_tube_status", definable_inline=False)

def add_oswrsc():
    subroutine(0xffb3, "oswrsc", None, None, hook=oswrsc_hook, is_entry_point=False)

def hardware_bbc():
    hardware(machinetype.MachineType.MACHINE_BBC)

def hardware_b_plus():
    hardware(machinetype.MachineType.MACHINE_BPLUS)

def hardware_master():
    hardware(machinetype.MachineType.MACHINE_MASTER)

def hardware_electron():
    hardware(machinetype.MachineType.MACHINE_ELECTRON)

def hardware_6502sp():
    hardware(machinetype.MachineType.MACHINE_6502SP)

def electron():
    mos_labels()
    hardware_electron()

def bbc():
    mos_labels()
    hardware_bbc()

def b_plus():
    mos_labels()
    add_oswrsc()
    hardware_b_plus()

def master():
    mos_labels()
    add_oswrsc()
    hardware_master()
