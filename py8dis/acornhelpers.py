"""
Acorn helpers

Helpers for the subroutine hooks that comment calls to an OS: acorn.py's
(and acornosbyte.py's OSBYTE hook), acornatom.py's, and commodore.py's too.
Given where a register is loaded with an immediate value before a call, they
write that value as a name: xy_addr() as the label of the address that two
registers hold (e.g. 'ldx #<block : ldy #>block' for the address of an OSWORD
parameter block), and enum_lookup() as a constant's name from a dictionary
(e.g. 'lda #osbyte_read_os_version').

What the BBC Micro and the Atom share is here too: os_call_name(), the
streams of characters code writes with OSWRCH (character_streams(), for the
comments on what's printed), and the snippets for loops that print with
OSWRCH (register_print_snippets()).

acorn.py imports them, so control files can use them as acorn.xy_addr and
acorn.enum_lookup too.
"""

from commands import *
from classification import INSIDE_A_CLASSIFICATION
import classification
import config
import disassembly
import session
from align import Align
from memorymanager import BinaryAddr, RuntimeAddr
from maker import make_lo, make_hi
from snippets6502 import register_code_snippet, OPCODE_TXA, OPCODE_TYA

def xy_addr(x_addr, y_addr):
    """The address whose low byte is at binary address x_addr and high byte at
    y_addr (usually the operands of 'ldx #lo' and 'ldy #hi' before an OS
    call), as a RuntimeAddr, with those bytes written as the label of that
    address. Returns None if either binary address is None, or nothing is
    loaded there.

    The label is found with get_label(), so one is made (auto-generated) if
    there isn't one. If x_addr is classified as a word and y_addr is the next
    byte, the word is written as the label; otherwise each byte that's byte
    data or part of an instruction is written as the label's low or high
    byte (e.g. 'ldx #<block')."""

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
    """Name the byte at reg_binary_addr (e.g. the operand of 'ldx #nn') from
    the dictionary 'e' ({value: name}, e.g. acorn.osbyte_enum), and return
    the byte, or None if reg_binary_addr is None.

    If the byte is in the dictionary, its name is defined as a constant
    (listed at the top of the output) and the byte is written as the name.
    The comment, if given, is added at the end of the line, whether or not
    the byte has a name."""

    if reg_binary_addr is None:
        return None
    r = memorymanager.memory_binary[reg_binary_addr]
    runtime_addr = movemanager.b2r(reg_binary_addr)
    if r in e:
        constant(r, e[r])
        auto_expr(runtime_addr, e[r])
    if comment is not None:
        auto_comment(runtime_addr, comment, align=Align.INLINE)
    return r

def os_call_name(name):
    """The name of an OS call, e.g. 'osbyte', in capitals (OSBYTE) unless
    config.set_upper_case_os_calls(False)."""
    return name.upper() if config.get_upper_case_os_calls() else name

# ************************************************************************************************
# The characters code writes with an OS call (e.g. OSWRCH), for the comments
# on them (acorn.comment_vdu_sequences() and acornatom's)

def character_streams(calls):
    """The streams of characters the code writes: for each straight run of
    code, the calls to the OS calls in 'calls' with no other call between
    them, as lists of VduChar. 'calls' gives each call's address and the
    characters it writes, None for A's: e.g. for the BBC Micro, {&ffee:
    [None], ..., &ffe7: [10, 13]} (OSWRCH, ..., and OSNEWL, which writes LF
    and CR; see acorn.py's _VDU_CALLS). A character is a number if it's
    known; 'X' or 'Y' if it's that register's, from TXA or TYA with the
    register unchanged since; or None. (OSWRCH preserves A, so A is the same
    for the next call unless an instruction between them changes it: it's
    the same character again, though not still X or Y if that register has
    changed.)

    Each stream is within one of cpu.straight_runs(), which end where other
    code jumps or branches in, and A's value comes from the pessimistic CPU
    state (what's known for certain)."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    streams = []
    for run in cpu.straight_runs():
        stream = []
        previous_char = None
        previous_call = None    # the index in the run of the previous call
        for k, binary_addr in enumerate(run):
            # Only a JSR or JMP (absolute) can be a call
            opcode = memory_binary[binary_addr]
            if opcode not in (0x20, 0x4c):
                continue
            target = memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]
            if target not in calls:
                if opcode == 0x20:
                    # Another call: it could write characters too
                    if stream:
                        streams.append(stream)
                    stream = []
                    previous_call = None
                continue
            # The instructions since the previous call (or the start of the
            # run), and the state just before this call (the state after the
            # instruction before it). set_at is where A was last set or
            # changed, if that's since the previous call.
            between = run[previous_call + 1:k] if previous_call is not None else run[:k]
            state = cpu.cpu_states[run[k - 1]] if k > 0 else None
            a = None if state is None else state.pessimistic['a']
            set_at = a.previous_adjust if a is not None and a.previous_adjust in between else None
            # The character: A's value if it's known; X or Y, if A was
            # transferred from one that hasn't changed since; or, if A hasn't
            # changed since the previous call, the same character again
            if a is not None and a.value is not None:
                char = a.value
            elif set_at is not None and memory_binary[set_at] in (OPCODE_TXA, OPCODE_TYA):
                reg = 'x' if memory_binary[set_at] == OPCODE_TXA else 'y'
                after = between[between.index(set_at) + 1:]
                unchanged = all(classification.get_classification(b).reg_changes[reg] in "-U" for b in after)
                char = reg.upper() if unchanged else None
            elif stream and previous_call is not None and all(classification.get_classification(b).reg_changes['a'] in "-U" for b in between):
                char = previous_char
                # (A holds what it held then, which is only still X or Y if
                # that register hasn't changed since either)
                if char in ('X', 'Y') and not all(classification.get_classification(b).reg_changes[char.lower()] in "-U" for b in between):
                    char = None
            else:
                char = None
            # Where the set-up starts: where A was set (or, for a value
            # transferred from another register, loaded), if that's since the
            # previous call, otherwise the call
            start = set_at if set_at is not None else binary_addr
            if a is not None and a.previous_load_imm in between:
                start = min(start, a.previous_load_imm)
            # One VduChar for each character the call writes (two for
            # OSNEWL, whose second starts at the call itself)
            for written in calls[target]:
                stream.append(VduChar(binary_addr, start, char if written is None else written, target))
                start = binary_addr
            previous_char = char
            previous_call = k
        if stream:
            streams.append(stream)
    return streams

class VduChar:
    """A character written by a call (see character_streams()): 'call', the call's
    binary address; 'start', the binary address where the code that sets up
    the character starts (where its comment goes); 'char', the character (a
    number, 'X', 'Y' or None); and 'target', the address called (e.g. &ffee
    for OSWRCH)."""

    __slots__ = ("call", "start", "char", "target")

    def __init__(self, call, start, char, target):
        self.call = call
        self.start = start
        self.char = char
        self.target = target

# ************************************************************************************************
# Loops that print with OSWRCH

def comment_print_message(p):
    """For a match of a loop that prints a message with OSWRCH, a character
    at a time (see register_snippets()), after tracing: comment it 'print
    message'."""
    # Make sure the branch instruction's operand jumps to the definition of the label as expected
    if not p.check_branch_matches('loop'):
        return

    disassembly.comment_binary(p.get_start_loc(), "print message", indent=1, align=Align.AFTER_LABEL, auto_generated=True)

def comment_print_repeated_character(p):
    """For a match of a loop that prints the same character several times
    with OSWRCH, counting down X (see register_snippets()), after tracing:
    comment it, e.g. 'print character 32 repeatedly', or 'A' for the
    character if it isn't loaded with an immediate value."""
    if not p.check_branch_matches('loop1') and not p.check_branch_matches('loop2'):
        return
    cc = p.get_memory('nn1')
    if cc is None:
        cc = 'A'

    disassembly.comment_binary(p.get_start_loc(), "print character {0} repeatedly".format(cc), indent=1, align=Align.AFTER_LABEL, auto_generated=True)

def register_print_snippets(oswrch):
    """Register the code snippets for loops that print with the OSWRCH at
    'oswrch' (&ffee on the BBC Micro, #fff4 on the Atom): a message, a
    character at a time, indexed by Y or by X (comment_print_message()), and
    the same character X times (comment_print_repeated_character()). (Called
    once per session, by acorn.register_snippets() or acornatom.atom().)"""
    # Printing a message, a character at a time: indexed by Y or by X
    register_code_snippet(comment_print_message, """
?   ldy #nn1 | ldy zp | ldy zp,x | ldy addr | ldy addr,x
loop
    lda message,y | lda zp,y | lda (zp1),y
?   bmi other | beq other
    jsr ${oswrch:04x}
    iny | dey
?   cpy #nn2
    bne loop | bpl loop
""".format(oswrch=oswrch))

    register_code_snippet(comment_print_message, """
?   ldx #nn1 | ldx zp | ldx zp,y | ldx addr | ldx addr,y
loop
    lda message,x | lda zp,x | lda (zp1,x)
?   bmi other | beq other
    jsr ${oswrch:04x}
    inx | dex
?   cpx #nn2
    bne loop | bpl loop
""".format(oswrch=oswrch))

    # Printing the same character X times
    register_code_snippet(comment_print_repeated_character, """
loop1
?   lda #nn1 | lda addr | lda zp | ldx #nn | ldx addr | ldx zp
?   lda #nn1 | lda addr | lda zp | ldx #nn | ldx addr | ldx zp
loop2
    jsr ${oswrch:04x}
    dex
    bne loop1 | bne loop2 | bpl loop1 | bpl loop2
""".format(oswrch=oswrch))
