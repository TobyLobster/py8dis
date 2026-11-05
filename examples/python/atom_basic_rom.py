"""The Acorn Atom's BASIC ROM (#C000-#CFFF), as a test on a real program,
with acorn.atom().

Atom BASIC isn't tokenised: it finds each keyword in the text as it runs,
with two matchers, each given a starting index in X, whose tables this
decodes to trace the routines and name them after their keywords:
- the keyword matcher at #C233 (#C231 with X=#ED, to skip a comma, if
  there is one: the commas between arguments are optional). Its
  table at #C000 holds, for each starting index, a list of first
  characters, then for each keyword the rest of its characters, ending
  with the high byte of the address of its routine (which has bit 7 set; #FE
  means no match, and #FF an error). A parallel table at #C0EE holds, at the
  same index, the routine's low byte (at a high byte), or the index to try
  next if the character doesn't match (at a character; at a first
  character, the index of its keywords). A keyword can be abbreviated with
  '.';
- the character matcher at #C27B (#C279 with X=#0E, to expect '='): single
  characters at #C1DD (ending with #FE or #FF, as above), with their
  routines' low bytes at #C1F8 and high bytes at #C212.
The other routines it traces are those the kernel calls (see
atom_kernel.py), named from the kernel's comments on them. An unknown
statement or function is passed on to the floating point ROM, if it's
there (#D000 holds #AA, #55, then the addresses of its handlers)."""

from commands import *
import acorn

load(0xc000, "orig/atom_basic_rom.orig", "6502", "872bb8f3fbaa941e56b694bd7dd5b333")
acorn.atom()

# The routines the kernel calls (from the commented disassembly of the kernel
# in floooh/emu-info, which says what they do)
for addr, name in [
        (0xc231, "skip_comma"),                 # (if there is one: it isn't an error if there isn't)
        (0xc278, "basic_rts"),                  # (also SHTVEC's default)
        (0xc2ac, "basic_brk"),                  # (RDRVEC's and STRVEC's default)
        (0xc2b2, "basic_start_2900"),           # with the text space at #2900 (as ATM files of BASIC programs run)
        (0xc2b6, "basic_start"),                # with the text space where it is (?18)
        (0xc2cf, None),
        (0xc3c8, "evaluate_expression_to_52"),  # (in #52-#55)
        (0xc3cb, "pop_to_52"),                  # (the workspace stack's last level, to #52-#55)
        (0xc3f1, "assign_expression"),          # ('=', then an expression, to the variable)
        (0xc434, "skip_spaces"),
        (0xc4e4, "check_end_of_statement"),
        (0xc4f6, "consolidate_text_pointer"),   # (and check for Escape)
        (0xc51d, None),
        (0xc550, "unknown_statement"),          # (the floating point ROM's, or an error)
        (0xc558, "next_statement"),
        (0xc55b, "next_statement_no_check"),
        (0xc589, "print_line_number"),
        (0xc5f9, "print_hex_number"),
        (0xc78b, None),
        (0xc8bc, "evaluate_expression"),        # (onto the workspace stack)
        (0xc94f, None),
        (0xc962, None),
        (0xca24, "unknown_function"),           # (the floating point ROM's, or an error)
        (0xca4c, "print_character"),            # (counting it in COUNT)
        (0xcd54, None),
        (0xcd9b, "end_program"),                # (updating TOP, back to direct mode)
        (0xce83, None)]:
    entry(addr, name)

# The matchers, and the one that expects '=' (the character matcher with
# X=#0E: an error if there isn't one)
label(0xc233, "match_keyword")
label(0xc27b, "match_character")
entry(0xc279, "expect_equals")
# The keyword matcher reads its table with 'lda #BFFF,x' (#BFFF is also the
# ROM latch)
for addr in (0xc242, 0xc251, 0xc265):
    expr(addr + 1, "keywords-1")

# The floating point ROM's identification, and the addresses of its handlers
# for unknown statements and functions (which BASIC jumps through, if the
# identification is there)
entry(0xc424, "check_fp_rom")    # (carry set if it's there)
label(0xd000, "fp_rom_id")
label(0xd002, "fp_rom_statement_handler")
label(0xd004, "fp_rom_function_handler")
expr(0xc42d, "fp_rom_id+1")

# The kernel's routines that the tables give (named as in atom_kernel.py):
# the one that tries the kernel's statements (PLOT etc.) for an unknown
# statement, its array variable test for an unknown function, and its RUN
kernel_routines = {0xf04b: "interpret_command", 0xf02e: "test_array_variable", 0xf141: "command_run"}
for addr, name in kernel_routines.items():
    label(addr, name)

# Names for the routines the matchers' tables give, by the starting index
# and the keyword (or character); the others get automatic names
names = {
    # The statements (X=#7D, and #7F, the same without NEW, SAVE and LIST)
    (0x7d, "!"): "statement_word_store", (0x7d, "?"): "statement_byte_store",
    (0x7d, "$"): "statement_string_store", (0x7d, "*"): "statement_os_command",
    # The functions (X=#07)
    (0x07, "#"): "function_hex", (0x07, "("): "function_bracket",
    (0x07, "!"): "function_word_fetch", (0x07, "?"): "function_byte_fetch",
    # The relational and logical operators
    (0x00, "<>"): "op_not_equal", (0x00, "<="): "op_less_or_equal", (0x00, "<"): "op_less",
    (0x00, "="): "op_equal", (0x00, ">="): "op_greater_or_equal", (0x00, ">"): "op_greater",
    (0x43, "OR"): "op_or", (0x43, "AND"): "op_and",
    # Keywords in statements
    (0x20, "THEN"): "if_then", (0x16, "TO"): "for_to", (0x1a, "STEP"): "for_step",
}
# The character matcher's, by the starting index and the character
char_names = {
    (0x00, "-"): "op_subtract", (0x00, "+"): "op_add", (0x00, "|"): "op_bitwise_or", (0x00, ":"): "op_bitwise_eor",
    (0x05, "*"): "op_multiply", (0x05, "/"): "op_divide", (0x05, "%"): "op_remainder",
    (0x05, "!"): "op_word_index", (0x05, "?"): "op_byte_index", (0x05, "&"): "op_bitwise_and",
    (0x18, "'"): "print_new_line", (0x18, '"'): "print_quoted_string",
}
# The prefix for the routines named after alphabetic keywords, by the
# starting index (e.g. 'statement_print', 'function_rnd')
prefixes = {0x7d: "statement_", 0x7f: "statement_", 0x07: "function_"}

# The starting indexes the code uses ('ldx #n' then 'jmp #C233' or 'jmp
# #C27B', found by searching the ROM; and #ED, at #C231)
keyword_starts = [0xed]
char_starts = [0x0e]
for addr in range(0xc000, 0xcffb):
    if memory[addr] == 0xa2 and memory[addr + 2] == 0x4c:
        target = memory[addr + 3] + 256 * memory[addr + 4]
        if target == 0xc233 and memory[addr + 1] not in keyword_starts:
            keyword_starts.append(memory[addr + 1])
        elif target == 0xc27b and memory[addr + 1] not in char_starts:
            char_starts.append(memory[addr + 1])

# The keyword matcher's tables
KEYWORDS = 0xc000 - 1       # (the table is read with 'lda #BFFF,x')
NEXT = 0xc0ee               # the parallel table
def keyword(x):
    return memory[KEYWORDS + x]

roles = {}          # what each index of the tables is: 'char' or 'high'
routines = {}       # the routine's name (or None) at each high byte's index
def routine(x, name):
    """The high byte at index x: its routine is named 'name' (if it isn't
    already named), if the byte is an address's (below #FE)."""
    roles[x] = "high"
    if keyword(x) < 0xfe and routines.get(x) is None:
        routines[x] = kernel_routines.get(keyword(x) * 256 + memory[NEXT + x], name)

for start in sorted(keyword_starts):
    # The first characters, then the high byte for no match
    x = start + 1
    firsts = []
    while not keyword(x) & 0x80:
        roles[x] = "char"
        firsts.append(x)
        x += 1
    routine(x, None)
    # Each first character's keywords
    for first in firsts:
        todo = [memory[NEXT + first]]
        seen = set()
        while todo:
            s = todo.pop()
            if s in seen:
                continue
            seen.add(s)
            text = chr(keyword(first))
            x = s + 1
            while not keyword(x) & 0x80:
                roles[x] = "char"
                text += chr(keyword(x))
                todo.append(memory[NEXT + x])
                x += 1
            name = names.get((start, text))
            if name is None and text.isalpha() and len(text) > 1 and start in prefixes:
                name = prefixes[start] + text.lower()
            routine(x, name)

# Mark the keyword table: runs of characters as strings, the high bytes as
# their routines' (with the low bytes in the parallel table), and the rest
# of the parallel table (the indexes) as bytes
label(0xc000, "keywords")
label(NEXT, "keyword_next")
x = 1
while KEYWORDS + x < NEXT:
    if roles.get(x) == "char":
        run = x
        while roles.get(x) == "char":
            x += 1
        string(KEYWORDS + run, x - run)
        continue
    if x in routines:
        code_ptr(NEXT + x, KEYWORDS + x, label_name=routines[x])
    else:
        byte(KEYWORDS + x)
    x += 1
for x in range(0, 0xef):
    if x not in routines:
        byte(NEXT + x)

# The character matcher's tables: the characters, then each one's routine
CHARS, CHARS_LOW, CHARS_HIGH = 0xc1dd, 0xc1f8, 0xc212
label(CHARS, "characters")
label(CHARS_LOW, "character_routines_low")
label(CHARS_HIGH, "character_routines_high")
end = max(char_starts)
for start in sorted(char_starts):
    x = start
    while not memory[CHARS + x] & 0x80:
        char(CHARS + x)
        code_ptr(CHARS_LOW + x, CHARS_HIGH + x, label_name=char_names.get((start, chr(memory[CHARS + x]))))
        x += 1
    byte(CHARS + x)
    end = max(end, x)
# (The low and high bytes for no match aren't used: the last's low byte is
# the first's high byte, and its high byte, #C22C, is the start of a routine
# that SGET and SPUT call)
for x in range(end):
    if memory[CHARS + x] & 0x80:
        byte(CHARS_LOW + x)
        byte(CHARS_HIGH + x)

# The powers of ten, 1 to 10^9, as four tables of bytes, least significant
# first (for printing numbers in decimal). The first table's last two bytes
# (10^8's and 10^9's, which are 0) are the second's first two.
for addr, name in ((0xc608, "powers_of_ten_byte_0"), (0xc610, "powers_of_ten_byte_1"),
                   (0xc61a, "powers_of_ten_byte_2"), (0xc624, "powers_of_ten_byte_3")):
    label(addr, name)
comment(0xc608, "The powers of ten, 1 to 10^9, as four tables of bytes, least significant first (the first table's last two bytes are the second's first two)")

# BASIC's default error handler, which is BASIC (the BRK handler runs the
# text at ?#10, which the reset sets to this): it prints ERROR, the error
# number and the line number, then a line 0 (whose number's zero high byte,
# at #CA1B, is also a BRK that code branches to)
label(0xc9e7, "default_error_handler")
comment(0xc9e7, "BASIC's default error handler, in BASIC: it prints ERROR, the error number (?0) and, if there is one, the line number")
comment(0xca1b, "A line 0 of BASIC (its line number's high byte is also a BRK)")

go()
