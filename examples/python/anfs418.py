"""ANFS 4.18, Acorn's Advanced Network Filing System, a sideways ROM for the
BBC Micro: a disassembly in progress (the XXX comments are open questions).
It uses acorn.bbc() and acorn.is_sideways_rom(), a move() for code the ROM
copies to &0400, constants for service call numbers, tables of command names
each followed by the address of the command's routine, jump tables split
into a table of low bytes and one of high bytes, hooks for subroutines that
are followed by a string to print or an error message, and many entry points
for code that tracing doesn't find by itself."""

from commands import *
import acorn
import config

load(0x8000, "orig/anfs418.orig", "6502", "0926bcb6f47458f8c4aed5364ff1122d")
#set_output_filename("anfs418.rom")

#config.set_show_cpu_state(True)

# Add labels specific to the BBC Micro
acorn.bbc()

# This is a sideways ROM, so it has a header and standard entry points we can label.
acorn.is_sideways_rom()

# Code at &bf04 that runs at &0400
move(0x400, 0xbf04, 0xbf95-0xbf04) # XXX: length is a guess

# Service call numbers, as names where the code checks for them
constant(0x01, "service_claim_absolute_workspace")
constant(0x0f, "service_vectors_changed")
expr(0x8a17, "service_vectors_changed")
expr(0x8a42, "service_claim_absolute_workspace")
expr(0x8ed9, "service_claim_absolute_workspace")
comment(0x8a1a, "Extra processing for vectors changed service call")
comment(0x8a45, "Extra processing for absolute workspace claim service call")
label(0x8a3c, "service_handler_common1")
label(0xbe62, "service_handler_tube_service_calls")
expr(0x8a63, "service_vectors_changed")
label(0x8a5a, "service_handler_common2")
label(0x8aa7, "service_handler_not_vectors_changed")
comment(0x8aae,
"""Call dispatch table entry X+1 for service calls 1<=X<&D.
Call dispatch table entry &D+1 for service call &12.
Don't handle any other service call.
(+1 because jump_table_dispatch_x_plus_y adds 1 if Y=0.)""")

# XXX: Jump table entry 0 is probably irrelevant.
# Jump table entries 1-&D inclusive are for service call handlers.
# There are probably some more given the use of Y by jump_table_dispatch_x_plus_y
comment(0x8e49, "Note that if Y=0, this will add 1 instead of 0.")
label(0x8e49, "jump_table_dispatch_x_plus_y")
label(0x89ef, "jump_table_high")
label(0x89ca, "jump_table_low")
label(0x8e58, "just_rts")
label(0x8ea5, "service_handler_claim_absolute_workspace")
label(0x8eb8, "service_handler_claim_private_workspace")

label(0x8eac, "clamp_absolute_workspace_and_save")

label(0x9611, "sta_e09_if_d6c_b7_set")
label(0x96b4, "error_template_minus_1")

# The tables of commands at &a3f0: each entry is the command's name (up to a
# byte with bit 7 set), that byte, then the address of its routine minus 1
# (for an RTS jump). There are groups of entries with a byte, or another
# address, between them, then six names each followed by three bytes.
pc = 0xa3f0
def stringhi_rts_code_ptr_block(n):
    """Mark n entries of a command table, starting at the global pc, and leave
    pc after them."""
    global pc
    for i in range(n):
        pc = stringhi(pc)
        pc += 1 # XXX: What's this byte mean?
        pc = rts_code_ptr(pc)
stringhi_rts_code_ptr_block(10)
pc += 1 # XXX: ?
stringhi_rts_code_ptr_block(17)
pc += 1 # XXX: ?
pc = rts_code_ptr(pc) # XXX: ?
stringhi_rts_code_ptr_block(2)
pc += 1
for i in range(6):
    pc = stringhi(pc)
    pc += 3

# XXX: At &864D there's some code to patch an address (probably a JMP/JSR
# operand) at &D3E/D3F using a pair of tables at &8869 (low byte) and &8861
# (high byte). abs,Y addressing is used and I don't currently know what range of
# values Y can have. The fact &8869 and &8861 are eight bytes apart suggests
# there are 8 possible values of Y. There's a table of RTS-compatible low bytes
# accessed via &8600,Y as well and looking at the data in the disassembly seems
# to suggest 8 possible values again and allows us to infer the first acceptable
# Y value is &81.
min_y = 0x81
for i in range(8):
    # There's a split table of code pointers for use via LDA:PHA:LDA:PHA:RTS at
    # &8869+x (low byte) and &8861+x (high byte).
    # XXX: Is this right? These code pointers appear to point into main RAM,
    # admittedly at locations which are potentially open for us to copy code to.
    code_ptr(0x8869 + min_y + i, 0x8861 + min_y + i)
    # There's also a low byte only table of code pointers at &8600+x; the high
    # byte of &86 is hard-coded at &8679. We manually do half of what code_ptr()
    # does; this could obviously be moved into commands.py as a standard
    # function but I am not sure it's useful enough.
    addr = 0x8600 + min_y + i
    code_at = (0x8600 + memory[addr]) + 1
    entry(code_at)
    lab = get_label(code_at, addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE)
    expr(addr, make_lo(make_subtract(lab, 1)))


#entry((0x421-0x400)+0xbf04, "copied_to_421")

# This subroutine prints non-top-bit-set characters following it, then continues
# execution at the first top-bit-set byte following it.
hook_subroutine(0x9145, "print_inline_top_bit_clear", stringhi_hook)

# This subroutine generates an error using the following NUL-terminated string.
# XXX: The fact there are two entry points suggests something slightly clever going on
def stringz_no_return_hook(target, addr):
    """Mark the string after the call, and say that the code doesn't carry on
    after it (the error doesn't return)."""
    stringz_hook(target, addr) # discard return address (the address after the string)
    return None
hook_subroutine(0x96b8, "generate_error_inline", stringz_no_return_hook)
hook_subroutine(0x96d4, "generate_error_inline2", stringz_no_return_hook)
hook_subroutine(0x96d1, "generate_error_inline3", stringz_no_return_hook)

# The jump table that jump_table_dispatch_x_plus_y uses: the addresses of
# routines minus 1 (for an RTS jump), the low bytes at jump_table_low and the
# high bytes at jump_table_high, from entry 1 (see the note about entry 0
# above)
for i in range(36):
    rts_code_ptr(0x89ca + 1 + i, 0x89ef + 1 + i)

def stringz_block(pc, n):
    """Mark n zero-terminated strings, one after another, from pc. (Not
    used.)"""
    for i in range(n):
        pc = stringz(pc)

# More code that tracing doesn't find by itself, and (with nonentry()) two
# places after a branch that's always taken, which aren't code
entry(0x80db)
entry(0x810d)
nonentry(0xa17c) # preceding BNE is always taken
entry(0x81dd)
entry(0x81e7)
entry(0x81fb)
entry(0x8244)
entry(0x82a1)
entry(0x8326)
entry(0x8396)
entry(0x8490)
entry(0x84ae)
entry(0x84b9)
entry(0x8543)
entry(0x86ea)
entry(0x8710)
entry(0x8732)
entry(0x874e)
entry(0x8762)
entry(0x87c1)
entry(0x87e6)
entry(0x8837)
entry(0x8884)
entry(0x8898)
entry(0x89a7)
entry(0x89b5)
string(0x8d61)
no_automatic_comment(0x8d61)
label(0x8e59, "print")
nonentry(0xaefb) # preceding BNE is always taken
entry(0x9935)
entry(0x9bbe)
entry(0x9e2f)
entry(0xa6e8)
entry(0xa707)
entry(0xa728)
entry(0xa72e)
entry(0xa734)
entry(0xa744)
entry(0xa7e4)
entry(0xa7ed)
entry(0xa802)
entry(0xa81a)
entry(0xa825)
entry(0xa8c5)
entry(0xa9e2)
entry(0xaaed)
expr(0xb01c, make_subtract("print", make_hex(0xf8)))
entry(0xb4ec)
entry(0xbcb3)
entry(0xbcc1)
entry(0xbccb)
entry(0xbcd6)
entry(0xbcf2)
entry(0xbd16)
entry(0xbd2a)
entry(0xbd3d)
entry(0xbd86)
entry(0xbd9b)
entry(0xbdfc)
entry(0xbe14)
entry(0xbe29)
entry(0xbe32)
entry(0xbe3b)
entry(0xbe59)
entry(0xbe62)
entry(0xbec3)
entry(0xbf95)
entry(0xbfd2)

go()
