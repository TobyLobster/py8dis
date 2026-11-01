"""
Regex snippets (6502)

Turns a regex snippet, a few lines of 6502 assembly describing a common piece
of code or data (see docs/snippets-and-hooks.md), into a regular expression
that matches its bytes in the binary. For example

    loop
        lda (zp1),y
        sta (zp2),y
        dey
        bne loop

becomes a regex for the bytes $b1 ?? $91 ?? $88 $d0 ??, where each ?? is any
byte. A name in an operand ('zp1', or 'loop' in 'bne loop') matches any
value, and a name on a line of its own ('loop') marks a position. Each
becomes a group in the regex, so that for a match, the snippet's functions
can find where each name is (see snippethelper.SnippetHelper).

The main pieces:
- parse_snippet() parses a whole snippet into a Snippet: the compiled regex,
  and 'labels', which gives the regex groups for each name;
- parse_line() parses one line (effectpattern.py uses it too, for an effect
  pattern's instruction lines), and parse_instruction() one instruction;
- parse_integer() reads a number ('31', '$1f', '&1f' or '%00011111');
- the tables: 'opcodes' (the opcode for each mnemonic and addressing mode),
  'addressing_mode_patterns' (what each addressing mode's operand looks
  like) and 'any_valid_instruction' (a regex for any one instruction, for
  '.').

snippets6502.py parses each snippet registered with this, and cpu6502.py
searches the binary's bytes for its regex, before and after tracing (see
snippets6502.py for how a match is used).

The instructions are the 65C02's (the 6502's, plus e.g. BRA, PHX, STZ, TSB
and '(zp)' addressing), not the 6502's undocumented ones. The regex only
looks at bytes, so a snippet matches wherever its bytes are, whether they
turn out to be code or data, and a name used in two places isn't checked to
have the same value in both.
"""

import re
import collections
import utils

class Snippet:
    """A parsed regex snippet. 'whole_pattern' is the compiled regex for its
    bytes (with re.DOTALL, so that '.' matches any byte, including $0a).
    'labels' is {name: [(group, is_position)]}: for each name in the
    snippet, the regex group for each place it's used, with is_position
    True for a name on a line of its own (an empty group, marking where the
    next line starts) and False for a name in an operand (a group of its one
    or two bytes). A name can have several groups, e.g. 'loop' for 'loop'
    and for 'bne loop', or one in each of several alternatives."""

    def __init__(self, whole_pattern, labels):
        self.whole_pattern = re.compile(bytes(whole_pattern), re.DOTALL | re.MULTILINE)
        self.labels = labels

    def __repr__(self):
        return f"{self.whole_pattern} {self.labels}"

# The opcode of each instruction a snippet can use, keyed by mnemonic and
# addressing mode (a name from addressing_mode_patterns, or 'implicit' for an
# instruction with no operand). These are the 65C02's instructions, laid out
# by the opcode's low nibble, then its high nibble; the commented out entries
# are opcodes with no instruction here. The instructions that can work on A
# (ASL, INA etc.) have an 'implicit' entry as well as an 'accumulator' one,
# so they can be written with no operand.
opcodes = {
        "brk implicit":  0x00,
        "bpl relative":  0x10,
        "jsr absolute":  0x20,
        "bmi relative":  0x30,
        "rti implicit":  0x40,
        "bvc relative":  0x50,
        "rts implicit":  0x60,
        "bvs relative":  0x70,
        "bra relative":  0x80,
        "bcc relative":  0x90,
        "ldy immediate": 0xA0,
        "bcs relative":  0xB0,
        "cpy immediate": 0xC0,
        "bne relative":  0xD0,
        "cpx immediate": 0xE0,
        "beq relative":  0xF0,

        "ora zeropageindexedindirectx": 0x01,
        "ora zeropageindexedindirecty": 0x11,
        "and zeropageindexedindirectx": 0x21,
        "and zeropageindexedindirecty": 0x31,
        "eor zeropageindexedindirectx": 0x41,
        "eor zeropageindexedindirecty": 0x51,
        "adc zeropageindexedindirectx": 0x61,
        "adc zeropageindexedindirecty": 0x71,
        "sta zeropageindexedindirectx": 0x81,
        "sta zeropageindexedindirecty": 0x91,
        "lda zeropageindexedindirectx": 0xA1,
        "lda zeropageindexedindirecty": 0xB1,
        "cmp zeropageindexedindirectx": 0xC1,
        "cmp zeropageindexedindirecty": 0xD1,
        "sbc zeropageindexedindirectx": 0xE1,
        "sbc zeropageindexedindirecty": 0xF1,

        #"": 0x02,
        "ora zeropageindirect": 0x12,
        #"": 0x22,
        "and zeropageindirect": 0x32,
        #"": 0x42,
        "eor zeropageindirect": 0x52,
        #"": 0x62,
        "adc zeropageindirect": 0x72,
        #"": 0x82,
        "sta zeropageindirect": 0x92,
        "ldx immediate": 0xA2,
        "lda zeropageindirect": 0xB2,
        #"": 0xC2,
        "cmp zeropageindirect": 0xD2,
        #"": 0xE2,
        "sbc zeropageindirect": 0xF2,

        #"": 0x03,
        #"": 0x13,
        #"": 0x23,
        #"": 0x33,
        #"": 0x43,
        #"": 0x53,
        #"": 0x63,
        #"": 0x73,
        #"": 0x83,
        #"": 0x93,
        #"": 0xA3,
        #"": 0xB3,
        #"": 0xC3,
        #"": 0xD3,
        #"": 0xE3,
        #"": 0xF3,

        "tsb zeropage":  0x04,
        "trb zeropage":  0x14,
        "bit zeropage":  0x24,
        "bit zeropagex": 0x34,
        #"": 0x44,
        #"": 0x54,
        "stz zeropage":  0x64,
        "stz zeropagex": 0x74,
        "sty zeropage":  0x84,
        "sty zeropagex": 0x94,
        "ldy zeropage":  0xA4,
        "ldy zeropagex": 0xB4,
        "cpy zeropage":  0xC4,
        #"": 0xD4,
        "cpx zeropage":  0xE4,
        #"": 0xF4,

        "ora zeropage":  0x05,
        "ora zeropagex": 0x15,
        "and zeropage":  0x25,
        "and zeropagex": 0x35,
        "eor zeropage":  0x45,
        "eor zeropagex": 0x55,
        "adc zeropage":  0x65,
        "adc zeropagex": 0x75,
        "sta zeropage":  0x85,
        "sta zeropagex": 0x95,
        "lda zeropage":  0xA5,
        "lda zeropagex": 0xB5,
        "cmp zeropage":  0xC5,
        "cmp zeropagex": 0xD5,
        "sbc zeropage":  0xE5,
        "sbc zeropagex": 0xF5,

        "asl zeropage":  0x06,
        "asl zeropagex": 0x16,
        "rol zeropage":  0x26,
        "rol zeropagex": 0x36,
        "lsr zeropage":  0x46,
        "lsr zeropagex": 0x56,
        "ror zeropage":  0x66,
        "ror zeropagex": 0x76,
        "stx zeropage":  0x86,
        "stx zeropagey": 0x96,
        "ldx zeropage":  0xA6,
        "ldx zeropagey": 0xB6,
        "dec zeropage":  0xC6,
        "dec zeropagex": 0xD6,
        "inc zeropage":  0xE6,
        "inc zeropagex": 0xF6,

        #"": 0x07,
        #"": 0x17,
        #"": 0x27,
        #"": 0x37,
        #"": 0x47,
        #"": 0x57,
        #"": 0x67,
        #"": 0x77,
        #"": 0x87,
        #"": 0x97,
        #"": 0xA7,
        #"": 0xB7,
        #"": 0xC7,
        #"": 0xD7,
        #"": 0xE7,
        #"": 0xF7,

        "php implicit": 0x08,
        "clc implicit": 0x18,
        "plp implicit": 0x28,
        "sec implicit": 0x38,
        "pha implicit": 0x48,
        "cli implicit": 0x58,
        "pla implicit": 0x68,
        "sei implicit": 0x78,
        "dey implicit": 0x88,
        "tya implicit": 0x98,
        "tay implicit": 0xA8,
        "clv implicit": 0xB8,
        "iny implicit": 0xC8,
        "cld implicit": 0xD8,
        "inx implicit": 0xE8,
        "sed implicit": 0xF8,

        "ora immediate": 0x09,
        "ora absolutey": 0x19,
        "and immediate": 0x29,
        "and absolutey": 0x39,
        "eor immediate": 0x49,
        "eor absolutey": 0x59,
        "adc immediate": 0x69,
        "adc absolutey": 0x79,
        "bit immediate": 0x89,
        "sta absolutey": 0x99,
        "lda immediate": 0xA9,
        "lda absolutey": 0xB9,
        "cmp immediate": 0xC9,
        "cmp absolutey": 0xD9,
        "sbc immediate": 0xE9,
        "sbc absolutey": 0xF9,

        "asl accumulator": 0x0A, "asl implicit": 0x0A,
        "ina accumulator": 0x1A, "ina implicit": 0x1A,
        "rol accumulator": 0x2A, "rol implicit": 0x2A,
        "dea accumulator": 0x3A, "dea implicit": 0x3A,
        "lsr accumulator": 0x4A, "lsr implicit": 0x4A,
        "phy implicit": 0x5A,
        "ror accumulator": 0x6A, "ror implicit": 0x6A,
        "ply implicit": 0x7A,
        "txa implicit": 0x8A,
        "txs implicit": 0x9A,
        "tax implicit": 0xAA,
        "tsx implicit": 0xBA,
        "dex implicit": 0xCA,
        "phx implicit": 0xDA,
        "nop implicit": 0xEA,
        "plx implicit": 0xFA,

        #"": 0x0B,
        #"": 0x1B,
        #"": 0x2B,
        #"": 0x3B,
        #"": 0x4B,
        #"": 0x5B,
        #"": 0x6B,
        #"": 0x7B,
        #"": 0x8B,
        #"": 0x9B,
        #"": 0xAB,
        #"": 0xBB,
        #"": 0xCB,
        #"": 0xDB,
        #"": 0xEB,
        #"": 0xFB,

        "tsb absolute":  0x0C,
        "trb absolute":  0x1C,
        "bit absolute":  0x2C,
        "bit absolutex": 0x3C,
        "jmp absolute":  0x4C,
        #"": 0x5C,
        "jmp absoluteindirect": 0x6C,
        "jmp absoluteindexedindirect": 0x7C,
        "sty absolute":  0x8C,
        "stz absolute":  0x9C,
        "ldy absolute":  0xAC,
        "ldy absolutex": 0xBC,
        "cpy absolute":  0xCC,
        #"": 0xDC,
        "cpx absolute":  0xEC,
        #"": 0xFC,

        "ora absolute":  0x0D,
        "ora absolutex": 0x1D,
        "and absolute":  0x2D,
        "and absolutex": 0x3D,
        "eor absolute":  0x4D,
        "eor absolutex": 0x5D,
        "adc absolute":  0x6D,
        "adc absolutex": 0x7D,
        "sta absolute":  0x8D,
        "sta absolutex": 0x9D,
        "lda absolute":  0xAD,
        "lda absolutex": 0xBD,
        "cmp absolute":  0xCD,
        "cmp absolutex": 0xDD,
        "sbc absolute":  0xED,
        "sbc absolutex": 0xFD,

        "asl absolute":  0x0E,
        "asl absolutex": 0x1E,
        "rol absolute":  0x2E,
        "rol absolutex": 0x3E,
        "lsr absolute":  0x4E,
        "lsr absolutex": 0x5E,
        "ror absolute":  0x6E,
        "ror absolutex": 0x7E,
        "stx absolute":  0x8E,
        "stz absolutex": 0x9E,
        "ldx absolute":  0xAE,
        "ldx absolutey": 0xBE,
        "dec absolute":  0xCE,
        "dec absolutex": 0xDE,
        "inc absolute":  0xEE,
        "inc absolutex": 0xFE,

        #"": 0x0F,
        #"": 0x1F,
        #"": 0x2F,
        #"": 0x3F,
        #"": 0x4F,
        #"": 0x5F,
        #"": 0x6F,
        #"": 0x7F,
        #"": 0x8F,
        #"": 0x9F,
        #"": 0xAF,
        #"": 0xBF,
        #"": 0xCF,
        #"": 0xDF,
        #"": 0xEF,
        #"": 0xFF,
}

# A regex for any one instruction in 'opcodes' (for '.' in a snippet): its
# opcode, then a '.' for each operand byte. The opcodes that are special
# characters in a regex ($24 '$', $28 '(', $29 ')', $2a '*', $2e '.', $5d ']',
# $5e '^', $7c '|' and $7d '}') are written with a doubled backslash
# ('\\x24' etc.), so that the regex sees the escape \x24 rather than the
# character itself. This must agree with 'opcodes'.
any_valid_instruction = \
    b'(?:\x00|\x10.|\x20..|\x30.|\x40|\x50.|\x60|\x70.|\x80.|\x90.|\xa0.|\xb0.|\xc0.|\xd0.|\xe0.|\xf0.|'+\
    b'\x01.|\x11.|\x21.|\x31.|\x41.|\x51.|\x61.|\x71.|\x81.|\x91.|\xa1.|\xb1.|\xc1.|\xd1.|\xe1.|\xf1.|'+\
    b'\x12.|\x32.|\x52.|\x72.|\x92.|\xa2.|\xb2.|\xd2.|\xf2.|'+\
    b'\x04.|\x14.|\\x24.|\x34.|\x64.|\x74.|\x84.|\x94.|\xa4.|\xb4.|\xc4.|\xe4.|'+\
    b'\x05.|\x15.|\x25.|\x35.|\x45.|\x55.|\x65.|\x75.|\x85.|\x95.|\xa5.|\xb5.|\xc5.|\xd5.|\xe5.|\xf5.|'+\
    b'\x06.|\x16.|\x26.|\x36.|\x46.|\x56.|\x66.|\x76.|\x86.|\x96.|\xa6.|\xb6.|\xc6.|\xd6.|\xe6.|\xf6.|'+\
    b'\x08|\x18|\\x28|\x38|\x48|\x58|\x68|\x78|\x88|\x98|\xa8|\xb8|\xc8|\xd8|\xe8|\xf8|'+\
    b'\x09.|\x19..|\\x29.|\x39..|\x49.|\x59..|\x69.|\x79..|\x89.|\x99..|\xa9.|\xb9..|\xc9.|\xd9..|\xe9.|\xf9..|'+\
    b'\x0a|\x1a|\\x2a|\x3a|\x4a|\x5a|\x6a|\x7a|\x8a|\x9a|\xaa|\xba|\xca|\xda|\xea|\xfa|'+\
    b'\x0c..|\x1c..|\x2c..|\x3c..|\x4c..|\x6c..|\\x7c..|\x8c..|\x9c..|\xac..|\xbc..|\xcc..|\xec..|'+\
    b'\x0d..|\x1d..|\x2d..|\x3d..|\x4d..|\\x5d..|\x6d..|\\x7d..|\x8d..|\x9d..|\xad..|\xbd..|\xcd..|\xdd..|\xed..|\xfd..|'+\
    b'\x0e..|\x1e..|\\x2e..|\x3e..|\x4e..|\\x5e..|\x6e..|\x7e..|\x8e..|\x9e..|\xae..|\xbe..|\xce..|\xde..|\xee..|\xfe..)'


# The mnemonics a snippet can use (those in 'opcodes')
mnemonics = {
    "adc", "and", "asl", "bcc", "bcs", "beq", "bit", "bmi", "bne", "bpl", "bra",
    "brk", "bvc", "bvs", "clc", "cld", "cli", "clv", "cmp", "cpx", "cpy", "dea",
    "dec", "dex", "dey", "eor", "inc", "ina", "inx", "iny", "jmp", "jsr", "lda",
    "ldx", "ldy", "lsr", "nop", "ora", "pha", "php", "phx", "phy", "pla", "plp",
    "plx", "ply", "rol", "ror", "rti", "rts", "sbc", "sec", "sed", "sei", "sta",
    "stx", "sty", "stz", "tax", "tay", "trb", "tsb", "tsx", "txa", "txs", "tya"
}

# Regular expressions for the parts of an operand, for the addressing modes'
# patterns below:
# - hex_or_decimal: a number, decimal with an optional sign, or hex after '$'
#   or '&' ('0x1f' matches too, but parse_integer() can't read it, and '%'
#   binary isn't accepted in an operand);
# - label_name: a name, which matches any value;
# - braced_index: a number in braces, e.g. '{0}', which is taken as a name;
# - zp_label_name: a name starting with 'zp', the only kind of name that can
#   be a zero page address (a name in an immediate or relative operand is
#   always one byte);
# - zp and expr: what a zero page operand, and any other operand, can be.
hex_or_decimal = r'[-+]?\d+|0x[0-9A-Fa-f]+|[$&][0-9A-Fa-f]+'
label_name     = r'[a-zA-Z_][a-zA-Z0-9_]*'
braced_index   = r'\{[0-9]+\}'
zp_label_name  = r'zp[a-zA-Z0-9_]*'
zp             = hex_or_decimal + '|' + zp_label_name + '|' + braced_index
expr           = hex_or_decimal + '|' + label_name + '|' + braced_index

class Details:
    """An addressing mode's operand: 'pattern', the regex its text must
    match (group 1 is the number or name in it), and 'length', the length of
    the instruction in bytes."""

    def __init__(self, pattern, length):
        self.pattern = pattern
        self.length = length

# The operand of each addressing mode. parse_instruction() tries a mnemonic's
# addressing modes in this order and takes the first that fits, so the zero
# page modes come before the absolute ones: a number below 256, or a 'zp'
# name, gives the zero page form.
addressing_mode_patterns = {
    'immediate':                Details(re.compile(r'^#(' + expr + r')$'), 2),                # e.g. #$10, #20 or #nn1 (a negative number matches, but parse_instruction() rejects it)
    'zeropagex':                Details(re.compile(r'^(' + zp + r'),[Xx]$'), 2),              # e.g. $FF,X (zero-page) or zp1,X
    'zeropagey':                Details(re.compile(r'^(' + zp + r'),[Yy]$'), 2),              # e.g. $FF,y (zero-page) or zp1,y
    'zeropageindexedindirectx': Details(re.compile(r'^\((' + zp + r'),[Xx]\)$'), 2),          # e.g. (zp1,X)
    'zeropageindexedindirecty': Details(re.compile(r'^\((' + zp + r')\),[Yy]$'),2),           # e.g. (zp1),Y
    'zeropageindirect':         Details(re.compile(r'^\((' + zp + r')\)$'), 2),               # e.g. (zp1)
    'zeropage':                 Details(re.compile(r'^(' + zp + r')$'), 2),                   # e.g. $FF (zero-page) or zp1
    'absoluteindexedindirect':  Details(re.compile(r'^\((' + expr + r'),[Xx]\)$'), 3),        # e.g. ($1234,X)
    'absoluteindirect':         Details(re.compile(r'^\((' + expr + r')\)$'), 3),             # e.g. ($1234)
    'absolutex':                Details(re.compile(r'^(' + expr + r'),[Xx]$'), 3),            # e.g. $ab12,X
    'absolutey':                Details(re.compile(r'^(' + expr + r'),[Yy]$'), 3),            # e.g. $123c,Y
    'absolute':                 Details(re.compile(r'^(' + expr + r')$'), 3),                 # e.g. $1000 (absolute) or addr1
    'relative':                 Details(re.compile(r'^([-+]?\d+|' + label_name + r')$'), 2),  # e.g. loop (any offset), or 12, the offset byte itself (a negative or hex number isn't accepted)
    'accumulator':              Details(re.compile(r'^A?$'), 1),                              # e.g. A or the empty string (but parse_instruction() deals with no operand itself, and 'absolute' takes 'A' as a name first)
}

# The addressing modes of each mnemonic (from 'opcodes'), in the order
# parse_instruction() tries them: that of addressing_mode_patterns, with
# 'implicit' (which isn't in it) last. E.g. for 'ldx': 'immediate',
# 'zeropagey', 'zeropage', 'absolutey', 'absolute'.
addr_modes_for_mnemonics = collections.defaultdict(list)

for m in mnemonics:
    for d in opcodes:
        if m+" " in d:
            addr_mode = d.split(" ")[1]
            addr_modes_for_mnemonics[m].append(addr_mode)


reference_order = addressing_mode_patterns.keys()
# Create a dictionary that maps addressing modes to their index in the reference list
order_dict = {mode: index for index, mode in enumerate(reference_order)}

# Sort each entry by addressing mode, using order_dict as a reference list
for mnem in addr_modes_for_mnemonics:
    addr_modes_for_mnemonics[mnem] = sorted(addr_modes_for_mnemonics[mnem], key=lambda mode: order_dict.get(mode, float('inf')))

def int_to_hex2(two_digit_int):
    """A regex escape for a byte, e.g. '\\x1f'."""
    return f"\\x{two_digit_int:02x}"

def int_to_hex4(four_digit_int):
    """'\\x' and a 16 bit number in four hex digits, e.g. '\\x1234'. (A
    regex reads that as the byte $12 followed by the characters '34', not as
    two bytes.)"""
    return f"\\x{four_digit_int:04x}"

def parse_line(line, group_number):
    """Parse one line of a snippet (see parse_snippet()), numbering its
    regex groups from group_number. Returns (pattern, labels, the next group
    number): the line's regex, or None if it has no instructions (e.g. a
    blank line); and the names in it, {name: [(group, is_position)]} as in
    Snippet, or None for an empty line or just a comment.

    A name at the very start of the line marks a position: its pattern is
    an empty group, and anything after the name is ignored (so an
    instruction must be indented, or it's taken as a name). Otherwise the
    line is one or more alternatives separated by '|', each an instruction or
    a sequence of instructions separated by ':'. A '?' first makes the line
    optional (but not a position: that's always there)."""
    line = line.split(';')[0]   # Remove comments

    if not line:                # skip empty lines
        return (None, None, group_number)

    optional = False
    if line[0] == '?':
        line = line[1:]
        optional = True

    if not line:
        return (None, None, group_number)

    labels = collections.defaultdict(list)

    # A position: an empty group, recorded as (group, True)
    m = re.match(r'^('+label_name + ')', line)
    if m:
        label = m.group(1)
        labels[label].append((group_number, True))
        group_number += 1
        return (b"()", labels, group_number)

    # The line's alternatives, separated by '|', each an instruction or a
    # sequence of instructions separated by ':' (e.g. 'lda #nn : sta $70 |
    # ldx #nn : stx $70')
    alternatives = []
    for alternative in line.split('|'):
        inst_result = bytearray()
        for inst in alternative.split(':'):
            seq_result, inst_labels, group_number = parse_instruction(inst, group_number)
            if seq_result:
                inst_result += seq_result
            for inst_label in inst_labels:
                labels[inst_label].extend(inst_labels[inst_label])
        if inst_result:
            alternatives.append(bytes(inst_result))

    if not alternatives:
        return (None, labels, group_number)
    pattern = bytearray(alternatives[0]) if len(alternatives) == 1 else bytearray(b"(?:" + b"|".join(alternatives) + b")")

    # An optional line matches if it can (the '?' is greedy): if its bytes
    # are there and the rest of the snippet still matches after them. So an
    # optional last line matches whenever its bytes follow.
    if optional:
        pattern = bytearray(b"(?:" + pattern + b")?")

    return(pattern, labels, group_number)

def parse_integer(s):
    """Parse a string as an integer, with an optional sign: hex after '$'
    or '&', binary after '%' (where '.' and '#' can be used for 0 and 1,
    e.g. '%..#.....'), otherwise decimal. Spaces and commas around it are
    ignored (so '!byte 1, 2' works). Raises ValueError (or IndexError, for
    an empty string) if it isn't a number; '0x1f' isn't one."""
    assert s is not None
    if s is None:
        return 0

    s = s.strip().strip(',')

    sign = 1
    if s[0] == '-':
        sign = -1
        s = s[1:]
    elif s[0] == '+':
        s = s[1:]

    if s[0] in '$&':
        # hexadecimal number
        s = int(s[1:], 16)
    elif s[0] == '%':
        # binary number
        s = s[1:].replace('.', '0').replace('#', '1')
        s = int(s, 2)
    else:
        # decimal number
        s = int(s)
    return sign * s

def parse_instruction(inst, group_number):
    """Parse one instruction of a snippet into a regex, numbering its groups
    from group_number. Returns (pattern, labels, the next group number), as
    parse_line() does (the pattern is None if 'inst' is blank).

    The instruction is a mnemonic and its operand, '.' (any instruction), or
    '!byte' or '!word' and numbers (those bytes, low byte first for a
    word). The addressing mode is the first of the mnemonic's (see
    addr_modes_for_mnemonics) whose operand pattern fits. A number in the
    operand matches just that value, and a name matches any one or two
    bytes (a group, recorded in labels as (group, False)). A number too big
    for one byte goes on to the next mode, so '$12' is zero page and '$1234'
    absolute.

    Raises ValueError for an unknown mnemonic, or an operand that doesn't fit
    any of its addressing modes."""
    labels = collections.defaultdict(list)

    inst = inst.strip()         # Remove any extra spaces and newlines
    if not inst:
        return (None, labels, group_number)

    # Split the inst into parts (mnemonic and operand)
    parts = inst.split(maxsplit=1)
    mnemonic = parts[0].lower()

    # '.': any one instruction
    if mnemonic == '.':
        result = any_valid_instruction
        return (result, labels, group_number)

    # '!byte': the bytes given, e.g. '!byte $01, $02'
    if mnemonic == "!byte":
        result = bytearray()
        for entry in parts[1].split():
            by = parse_integer(entry)
            result += re.escape(bytearray([by]))
        return (result, labels, group_number)

    # '!word': the 16 bit values given, each low byte first
    if mnemonic == "!word":
        result = bytearray()
        for entry in parts[1].split():
            by = parse_integer(entry)
            result += re.escape(bytearray([by & 255, by >> 8]))
        return (result, labels, group_number)

    if mnemonic not in mnemonics:
        raise ValueError(f"Unknown mnemonic: {mnemonic}")

    operand = parts[1].strip() if len(parts) > 1 else None

    # Identify addressing mode and parse operand
    details = None
    operand_expr = None
    match_groups = None
    result_operand = bytearray()
    instruction_template = mnemonic
    if not operand:
        # No operand: the implicit form, or failing that the accumulator one
        details = Details(re.compile(""), 1)
        instruction_template = mnemonic + " implicit"
        if not instruction_template in opcodes:
            details = Details(re.compile("[Aa]|"), 1)
            instruction_template = mnemonic + " accumulator"
    else:
        for addressing_mode in addr_modes_for_mnemonics[mnemonic]:
            details = addressing_mode_patterns[addressing_mode]
            m = re.match(details.pattern, operand)
            if m:
                match_groups = m.group()
                # (Only an operand of more than one character is read. One
                # of just one character, e.g. 'A', 'sta 7' or 'lda n', is
                # skipped, leaving just the opcode in the pattern.)
                if len(m.group()) > 1:
                    # Record the matches if they are labels, or check the values if they are integers.
                    # (A number starts with a sign, '&', '$' or a digit; anything else is a name.)
                    operand_expr = m.group(1)
                    is_integer = operand_expr and (operand_expr[0] in '+-&$0123456789')
                    if is_integer:
                        operand_expr = parse_integer(operand_expr)

                    # check instruction length
                    if details.length == 2:
                        # A one byte operand: a number from 0 to 255, or a
                        # name, which is any byte, in a group of its own
                        if is_integer:
                            if (operand_expr >= 0) and (operand_expr < 256):
                                result_operand += re.escape(bytearray([operand_expr]))
                            else:
                                # Too big (or negative) for one byte, so try
                                # the mnemonic's next addressing mode (e.g.
                                # absolute rather than zero page)
                                continue
                        else:
                            labels[operand_expr] = [(group_number, False)]
                            result_operand += "(.)".encode()
                            group_number += 1
                    elif details.length == 3:
                        # A two byte operand: a number (low byte first), or
                        # a name, which is any two bytes, in a group
                        if is_integer:
                            result_operand += re.escape(bytearray([operand_expr & 255, operand_expr >> 8]))
                        else:
                            labels[operand_expr] = [(group_number, False)]
                            result_operand += "(..)".encode()
                            group_number += 1
                    else:
                        assert False
                # found match_groups, labels, mnemonic, and details: (addressing_mode and length)
                # look up the opcode based on the mnemonic and the addressing_mode
                instruction_template = mnemonic + " " + addressing_mode
                break

    # (details is None only if the mnemonic has no addressing modes to try.
    # An operand that fits none of them leaves instruction_template as just
    # the mnemonic, which the check after this catches.)
    if details is None:
        raise ValueError(f"Invalid operand format: {operand}")

    if not instruction_template in opcodes:
        raise ValueError(f"Invalid operand for instruction: {instruction_template}, operand {operand}")

    opcode = opcodes[instruction_template]
    result = re.escape(bytearray([opcode]))+result_operand

    # Return the pattern, the names in it and the next group number
    return (result, labels, group_number)

def parse_snippet(program):
    """Make a Snippet (a regular expression for the bytes) from a snippet's
    lines of 6502 assembly, one per line:

    - an instruction, indented, e.g. '    lda #$1f' or '    jsr $ffee'. An
      operand that's a name rather than a number matches any value, and
      records where it is, for SnippetHelper.get_memory() etc.: a one byte
      operand ('lda #nn1'), a two byte one ('lda message,y'), or a zero page
      one if the name starts with 'zp' ('lda (zp1),y');
    - '.', any instruction;
    - '!byte' or '!word' and numbers, those bytes;
    - alternatives, separated by '|', e.g. '    lda #nn1 | txa | tya';
    - a sequence of instructions, separated by ':', which is useful as an
      alternative, e.g. '    lda #nn1 : sta $70 | ldx #nn1 : stx $70';
    - '?' at the start of the line makes the line optional;
    - a name, not indented, records the position (e.g. a loop's start);
    - ';' starts a comment.

    A number in an operand is decimal, or hex after '$' or '&'. The lines'
    patterns are joined, so the snippet matches only where its instructions
    are one after another in the binary. An optional line is matched if its
    bytes are there and the rest of the snippet still matches after them. A
    name used more than once (e.g. 'nn1' in two alternatives) isn't checked
    to have the same value each time: SnippetHelper gives the first place it
    matched.

    Raises ValueError (from parse_instruction()) for an instruction it can't
    parse."""
    # parse the program into a whole_pattern
    whole_pattern = bytearray()
    whole_labels = collections.defaultdict(list)
    # (Group 0 is the whole match, so the names' groups start at 1)
    group_number = 1

    for line in program.splitlines():
        pattern, labels, group_number = parse_line(line, group_number)
        if pattern:
            whole_pattern += pattern
        if labels:
            for label in labels:
                whole_labels[label].extend(labels[label])

    return Snippet(whole_pattern, whole_labels)
