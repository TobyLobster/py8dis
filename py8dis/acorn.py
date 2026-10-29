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
from memorymanager import BinaryAddr, BinaryLocation, RuntimeAddr
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from snippets6502 import register_snippet, register_code_snippet, register_data_snippet, OPCODE_TXA, OPCODE_TYA
from snippethelper import vector_pattern, vector_handler, vector_handler_name, comment_vector, half_set_vector_text

# The data tables (OS call names, INKEY numbers etc), which control files can
# use as e.g. acorn.inkey_enum
from acorntables import *

# Helpers shared by the OS call hooks
from acornhelpers import xy_addr, enum_lookup

# OSBYTE (its descriptions, and the hook that uses them)
from acornosbyte import osbyte_hook


# ************************************************************************************************
def pre_trace_writing_to_vector(p):
    """Code setting one of the vectors (an effect pattern, see
    snippethelper.vector_pattern()): before tracing, label the handler (e.g.
    'handle_brkv', then 'handle_brkv_2' etc) and trace it."""
    vector = p.binding('vector')
    # The number of handlers found so far for each vector, for naming them
    vector_handler_count = session.current().extras.setdefault("acorn.vector_handler_count", {})

    def new_name():
        if vector not in vector_handler_count:
            vector_handler_count[vector] = 2
            return "handle_{0}".format(vectors[vector])
        name = "handle_{0}_{1}".format(vectors[vector], vector_handler_count[vector])
        vector_handler_count[vector] += 1
        return name

    vector_handler(p, new_name)

def post_trace_writing_to_vector(p):
    """Code setting one of the vectors: after tracing, comment it (e.g. "Set
    BRK vector to 'handle_brkv'", or for one with only one byte set to a
    known value, "Set the low byte of econet vector to &36"), and write the
    handler's address as its name's low and high bytes."""
    vector = p.binding('vector')
    description = vector_descriptions[vector]
    if p.matched('lo') and p.matched('hi'):
        name = vector_handler_name(p.value('lo_value') + 256 * p.value('hi_value'))
        text = "Set {0} to '{1}'".format(description, name)
    else:
        text = half_set_vector_text(p, description, config.get_assembler().hex2)
        # A vector set to its extended vector entry (&ff00 + 3 * its number),
        # which calls the routine in the extended vector table for a paged ROM
        extended = 0xff00 + 3 * ((vector - 0x200) // 2)
        if p.matched('lo') and not p.matched('hi') and p.value('lo_value') == extended & 0xff:
            text += " (its extended vector entry, {0}, if the high byte is {1})".format(
                config.get_assembler().hex4(extended), config.get_assembler().hex2(extended >> 8))
    comment_vector(p, text)

# ************************************************************************************************
# ************************************************************************************************
# VDU sequences: the characters code writes with OSWRCH, decoded as VDU
# commands

# OSWRCH and the other calls that write characters: their addresses, and the
# characters each writes (None for A's)
_VDU_CALLS = {0xffee: [None], 0xffcb: [None], 0xffe3: [None], 0xffe7: [10, 13]}

def _vdu_streams():
    """The streams of characters the code writes: for each straight run of
    code, the calls to OSWRCH (and OSASCI, OSNEWL and NVWRCH) with no other
    call between them, as lists of VduChar. A character is a number if it's
    known; 'X' or 'Y' if it's that register's, from TXA or TYA with the
    register unchanged since; or None. (OSWRCH preserves A, so A is the same
    for the next call unless an instruction between them changes it.)"""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    streams = []
    for run in cpu.straight_runs():
        stream = []
        previous_char = None
        previous_call = None    # the index in the run of the previous call
        for k, binary_addr in enumerate(run):
            opcode = memory_binary[binary_addr]
            if opcode not in (0x20, 0x4c):
                continue
            target = memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]
            if target not in _VDU_CALLS:
                if opcode == 0x20:
                    # Another call: it could write characters too
                    if stream:
                        streams.append(stream)
                    stream = []
                    previous_call = None
                continue
            between = run[previous_call + 1:k] if previous_call is not None else run[:k]
            state = cpu.cpu_states[run[k - 1]] if k > 0 else None
            a = None if state is None else state.pessimistic['a']
            set_at = a.previous_adjust if a is not None and a.previous_adjust in between else None
            if a is not None and a.value is not None:
                char = a.value
            elif set_at is not None and memory_binary[set_at] in (OPCODE_TXA, OPCODE_TYA):
                reg = 'x' if memory_binary[set_at] == OPCODE_TXA else 'y'
                after = between[between.index(set_at) + 1:]
                unchanged = all(classification.get_classification(b).reg_changes[reg] in "-U" for b in after)
                char = reg.upper() if unchanged else None
            elif stream and previous_call is not None and all(classification.get_classification(b).reg_changes['a'] in "-U" for b in between):
                char = previous_char
            else:
                char = None
            # Where the set-up starts: where A was set (or, for a value
            # transferred from another register, loaded), if that's since the
            # previous call, otherwise the call
            start = set_at if set_at is not None else binary_addr
            if a is not None and a.previous_load_imm in between:
                start = min(start, a.previous_load_imm)
            for written in _VDU_CALLS[target]:
                stream.append(VduChar(binary_addr, start, char if written is None else written, target))
                start = binary_addr
            previous_char = char
            previous_call = k
        if stream:
            streams.append(stream)
    return streams

class VduChar:
    """A character written by a call (see _vdu_streams()): the call's binary
    address, where the code that sets up the character starts, the character,
    and the address called (e.g. &ffee for OSWRCH)."""

    __slots__ = ("call", "start", "char", "target")

    def __init__(self, call, start, char, target):
        self.call = call
        self.start = start
        self.char = char
        self.target = target

# VDU 0 and 27 do nothing, so a zero in a stream is much more likely to be a
# parameter of an earlier command than a command, and they don't count as
# explaining any characters (see _vdu_parse())
_VDU_NO_OPS = (0, 27)

def _vdu_parse(chars, start):
    """Parse the characters (see _vdu_streams()) as VDU commands, from index
    start: [(index, length)] for each command, and the number of characters
    covered by the commands that are known (their first character is), other
    than VDU 0 and 27. A
    character that isn't known where a command starts is taken to be one
    character (written as itself, e.g. a digit). Parsing stops at a command
    that runs past the end."""
    commands = []
    covered = 0
    i = start
    while i < len(chars):
        code = chars[i]
        if not isinstance(code, int):
            commands.append((i, 1))
            i += 1
            continue
        length = 1 + (vdu_parameter_counts.get(code, 0) if code < 32 else 0)
        if i + length > len(chars):
            break
        commands.append((i, length))
        if code not in _VDU_NO_OPS:
            covered += length
        i += length
    return commands, covered

def _vdu_best_parse(chars):
    """The most likely way to parse the characters as VDU commands. The
    first few may be the end of a command that earlier code started, so this
    tries starting at each of the first ten characters (a command has at most
    nine parameters), and takes the parse that explains the most characters
    (see _vdu_parse()): longer runs of commands that fit are more likely to
    be right. Of those, it takes the one with fewer, so longer, known commands, and
    then the earliest start. Returns (start, commands, characters
    explained)."""
    best = None
    for start in range(0, min(10, len(chars))):
        commands, covered = _vdu_parse(chars, start)
        known = sum(1 for index, length in commands if isinstance(chars[index], int))
        score = (covered, -known, -start)
        if best is None or score > best[0]:
            best = (score, start, commands, covered)
    return best[1], best[2], best[3]

def _vdu_description(code, params):
    """What a VDU command does, e.g. 'Select mode 4', from its code and
    parameters (numbers, 'X', 'Y' or None)."""
    def p(v):
        return "?" if v is None else str(v)
    def word(lo, hi):
        if isinstance(lo, int) and isinstance(hi, int):
            v = lo + 256 * hi
            return str(v - 65536 if v >= 32768 else v)
        return "?"
    if code in vdu_descriptions:
        return vdu_descriptions[code]
    if code == 1:
        return "Send character {0} to the printer only".format(p(params[0]))
    if code == 17:
        c = params[0]
        if isinstance(c, int) and c >= 128:
            return "Set the text background colour to {0}".format(c - 128)
        return "Set the text colour to {0}".format(p(c))
    if code == 18:
        c = params[1]
        if isinstance(c, int) and c >= 128:
            return "Set the graphics background colour to {0} (plot action {1})".format(c - 128, p(params[0]))
        return "Set the graphics colour to {0} (plot action {1})".format(p(c), p(params[0]))
    if code == 19:
        return "Set logical colour {0} to physical colour {1}".format(p(params[0]), p(params[1]))
    if code == 22:
        return "Select mode {0}".format(p(params[0]))
    if code == 23:
        n = params[0]
        if n == 0:
            return "Set CRTC register {0} to {1}".format(p(params[1]), p(params[2]))
        if n == 1:
            if params[1] == 0:
                return "Turn the cursor off"
            if params[1] == 1:
                return "Turn the cursor on"
        if isinstance(n, int) and n >= 32:
            return "Define character {0}".format(n)
        return "VDU 23,{0}".format(p(n))
    if code == 24:
        return "Set the graphics window to ({0},{1})-({2},{3})".format(word(*params[0:2]), word(*params[2:4]), word(*params[4:6]), word(*params[6:8]))
    if code == 25:
        return "PLOT {0},{1},{2}".format(p(params[0]), word(*params[1:3]), word(*params[3:5]))
    if code == 28:
        return "Set the text window to ({0},{1})-({2},{3})".format(*(p(v) for v in params))
    if code == 29:
        return "Set the graphics origin to ({0},{1})".format(word(*params[0:2]), word(*params[2:4]))
    if code == 31:
        return "Position text cursor at ({0},{1})".format(p(params[0]), p(params[1]))
    return None

def _vdu_text(chars):
    """A comment for printable characters (all known numbers), e.g. 'Print
    "Hello"', or 'Print characters 32, 224, 225'."""
    if all(32 <= c < 127 and c != 34 for c in chars):
        return 'Print "{0}"'.format("".join(chr(c) for c in chars))
    return "Print characters {0}".format(", ".join(str(c) for c in chars))

def comment_vdu_sequences():
    """Comment the VDU commands that code writes with OSWRCH (e.g. 'Select
    mode 4' before 'lda #22 : jsr oswrch : lda #4 : jsr oswrch'), however A
    is set, and runs of two or more printable characters. Since a stream of
    calls can start part way through a command that earlier code started,
    the parse used is the one that explains the most characters (see
    _vdu_best_parse()); if that skips some first characters, they're
    commented as the end of an earlier sequence. (Run once the code has been
    traced, as an analysis hook.)"""
    moves = session.current().moves.move_id_for_binary_addr

    def comment(binary_addr, text):
        disassembly.comment_binary(BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text, indent=1, align=Align.AFTER_LABEL, auto_generated=True)

    for stream in _vdu_streams():
        chars = [c.char for c in stream]
        start, commands, covered = _vdu_best_parse(chars)
        if covered == 0:
            continue
        if start > 0:
            comment(stream[0].start, "The end of a VDU sequence that earlier code started")
        printable = []      # (index, char) of the run of printable characters so far

        def end_printable():
            if len(printable) >= 2:
                comment(stream[printable[0][0]].start, _vdu_text([c for _, c in printable]))
            printable.clear()

        skip = set()
        for n, (index, length) in enumerate(commands):
            code = chars[index]
            if not isinstance(code, int) or index in skip:
                end_printable()
                continue
            if code >= 32 and code != 127:
                printable.append((index, code))
                continue
            end_printable()
            if stream[index].target == 0xffe7:
                # (OSNEWL, whose hook comments it)
                continue
            if code == 13 and stream[index].target == 0xffe3:
                # (OSASCI writes CR as a new line)
                comment(stream[index].start, "Start a new line")
                continue
            if code in (10, 13) and n + 1 < len(commands) and chars[commands[n + 1][0]] == 23 - code and stream[commands[n + 1][0]].target != 0xffe7:
                # CR and LF, or LF and CR
                comment(stream[index].start, "Start a new line")
                skip.add(commands[n + 1][0])
                continue
            text = _vdu_description(code, chars[index + 1:index + length])
            if text is not None:
                comment(stream[index].start, text)
        end_printable()

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
    # Code setting one of the vectors at &0200-&0235, in any order, with any
    # registers (an effect pattern)
    register_snippet(pre_trace_writing_to_vector, post_trace_writing_to_vector, vector_pattern(addr for addr in vectors if addr % 2 == 0))

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
    if comment_vdu_sequences not in session.current().trace.analysis_hooks:
        session.current().trace.analysis_hooks.append(comment_vdu_sequences)
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
    # ENHANCE: If bit 5 of the ROM type is set, a Tube relocation address
    # follows the copyright string, which could be labelled.

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
