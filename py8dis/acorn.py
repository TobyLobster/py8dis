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

# Helpers shared by the OS call hooks
from acornhelpers import xy_addr, enum_lookup

# OSBYTE (its descriptions, and the hook that uses them)
from acornosbyte import osbyte_hook


# ************************************************************************************************
def pre_trace_writing_to_vector(p):
    p.entry()

    stored = p.stored_values(['nn1', 'nn2'], ['first_store', 'second_store'])
    if stored is None:
        return
    (addr1, nn1, nn1_addr), (addr2, nn2, nn2_addr) = stored
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
    # Code setting one of the vectors at &0200-&0235
    vector_addrs = range(0x200, 0x236)
    # Any store to one of them, e.g. 'sta $200 | ... | sty $235'
    stores = " | ".join("st{0} ${1:x}".format(reg, addr) for reg in "axy" for addr in vector_addrs)
    # Any load and store to one of them, e.g. 'lda #nn1 : sta $200 | ...'
    def pairs(n):
        return " | ".join("ld{0} #nn{1} : st{0} ${2:x}".format(reg, n, addr) for reg in "axy" for addr in vector_addrs)
    # Two loads into different registers, e.g. 'ldx #nn1 : ldy #nn2 | ...'
    loads = " | ".join("ld{0} #nn1 : ld{1} #nn2".format(reg1, reg2) for reg1 in "axy" for reg2 in "axy" if reg1 != reg2)

    # e.g. 'lda #<handler : sta $206 : lda #>handler : sta $207' (with A, X or
    # Y for each)
    register_snippet(pre_trace_writing_to_vector, None, """
first_store
    {0}
second_store
    {1}
end
""".format(pairs(1), pairs(2)))
    # e.g. 'ldx #<handler : ldy #>handler : stx $206 : sty $207' (with any two
    # registers, and the stores in either order)
    register_snippet(pre_trace_writing_to_vector, None, """
    {0}
first_store
    {1}
second_store
    {1}
end
""".format(loads, stores))


# ************************************************************************************************
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
    """Name the hardware addresses of the given machine (see hardware_labels in
    acorntables.py), or the Tube registers for the 6502 second processor."""
    if machine == machinetype.MachineType.MACHINE_6502SP:
        label_tube(0xfef8, "parasite")
        return

    for hardware_label in hardware_labels:
        if machine in hardware_label.machines:
            optional_label(hardware_label.addr, hardware_label.name, definable_inline=hardware_label.definable_inline)

    if machine != machinetype.MachineType.MACHINE_ELECTRON:
        # Name the CRTC register numbers stored to crtc_address_register
        for instruction, reg in [("sta crtc_address_register", 'a'), ("stx crtc_address_register", 'x'), ("sty crtc_address_register", 'y')]:
            session.current().trace.substitute_constant_list.append(cpu6502.SubConst(instruction, reg, crtc_registers_enum, True))

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
