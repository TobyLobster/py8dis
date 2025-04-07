import re
import collections
import utils

class Snippet:
    def __init__(self, whole_pattern, labels):
        self.whole_pattern = re.compile(bytes(whole_pattern), re.DOTALL | re.MULTILINE)
        self.labels = labels

    def __repr__(self):
        return f"{self.whole_pattern} {self.labels}"

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

any_valid_instruction = \
    b'(?:\x00|\x10.|\x20..|\x30.|\x40|\x50.|\x60|\x70.|\x80.|\x90.|\xa0.|\xb0.|\xc0.|\xd0.|xe0.|\xf0.|'+\
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


mnemonics = {
    "adc", "and", "asl", "bcc", "bcs", "beq", "bit", "bmi", "bne", "bpl", "bra",
    "brk", "bvc", "bvs", "clc", "cld", "cli", "clv", "cmp", "cpx", "cpy", "dea",
    "dec", "dex", "dey", "eor", "inc", "ina", "inx", "iny", "jmp", "jsr", "lda",
    "ldx", "ldy", "lsr", "nop", "ora", "pha", "php", "phx", "phy", "pla", "plp",
    "plx", "ply", "rol", "ror", "rti", "rts", "sbc", "sec", "sed", "sei", "sta",
    "stx", "sty", "stz", "tax", "tay", "trb", "tsb", "tsx", "txa", "txs", "tya"
}

# Regular expression patterns for different addressing modes
hex_or_decimal = r'[-+]?\d+|0x[0-9A-Fa-f]+|[$&][0-9A-Fa-f]+'
label_name     = r'[a-zA-Z_][a-zA-Z0-9_]*'
braced_index   = r'\{[0-9]+\}'
zp_label_name  = r'zp[a-zA-Z0-9_]*'
zp             = hex_or_decimal + '|' + zp_label_name + '|' + braced_index
expr           = hex_or_decimal + '|' + label_name + '|' + braced_index

class Details:
    def __init__(self, pattern, length):
        self.pattern = pattern
        self.length = length

addressing_mode_patterns = {
    'immediate':                Details(re.compile(r'^#(' + expr + r')$'), 2),                # e.g. #$10, #-20, or #label_name_name
    'zeropagex':                Details(re.compile(r'^(' + zp + r'),[Xx]$'), 2),              # e.g. $FF,X (zero-page) or zp1,X
    'zeropagey':                Details(re.compile(r'^(' + zp + r'),[Yy]$'), 2),              # e.g. $FF,y (zero-page) or zp1,y
    'zeropageindexedindirectx': Details(re.compile(r'^\((' + zp + r')\),[Xx]$'), 2),          # e.g. (zp1),X
    'zeropageindexedindirecty': Details(re.compile(r'^\((' + zp + r')\),[Yy]$'),2),           # e.g. (zp1),Y
    'zeropageindirect':         Details(re.compile(r'^\((' + zp + r')\)$'), 2),               # e.g. (zp1)
    'zeropage':                 Details(re.compile(r'^(' + zp + r')$'), 2),                   # e.g. $FF (zero-page) or zp1
    'absoluteindexedindirect':  Details(re.compile(r'^\((' + expr + r'),[Xx]\)$'), 3),        # e.g. ($1234,X)
    'absoluteindirect':         Details(re.compile(r'^\((' + expr + r')\)$'), 3),             # e.g. ($1234)
    'absolutex':                Details(re.compile(r'^(' + expr + r'),[Xx]$'), 3),            # e.g. $ab12,X
    'absolutey':                Details(re.compile(r'^(' + expr + r'),[Yy]$'), 3),            # e.g. $123c,Y
    'absolute':                 Details(re.compile(r'^(' + expr + r')$'), 3),                 # e.g. $1000 (absolute) or addr1
    'relative':                 Details(re.compile(r'^([-+]?\d+|' + label_name + r')$'), 2),  # e.g. -7 (signed byte offset) or label1
    'accumulator':              Details(re.compile(r'^A?$'), 1),                              # e.g. A or the empty string
}

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

def parse_integer_string(current_string):
    if not current_string:
        None

    is_decimal = current_string and (current_string[0] in ['+-0123456789'])
    is_hex     = current_string and (current_string[0] in ['&$'])
    is_binary  = current_string and (current_string[0] in ['%'])

    if is_decimal:
        return int(current_string)
    elif is_hex:
        return int(current_string[1:], 16)
    elif is_binary:
        return int(current_string[1:], 2)
    return None

def check_integer_matches_memory(current_string, expected_int):
    current_int = parse_integer_string()
    return current_int == expected_int

def int_to_hex2(two_digit_int):
    return f"\\x{two_digit_int:02x}"

def int_to_hex4(four_digit_int):
    return f"\\x{four_digit_int:04x}"

# Parse a line of 6502 assembly
def parse_line(line, group_number):
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
    pattern = bytearray()

    if optional:
        pattern += "(?:".encode()

    m = re.match(r'^('+label_name + ')', line)
    if m:
        label = m.group(1)
        labels[label].append((group_number, True))
        group_number += 1
        return (b"()", labels, group_number)

    index = 0
    for inst in line.split('|'):
        inst_result, inst_labels, group_number = parse_instruction(inst, group_number)
        if inst_result:
            if index == 1:
                pattern = "(?:".encode() + pattern
            pattern += "|".encode()+inst_result if pattern else inst_result
            index += 1
        for inst_label in inst_labels:
            labels[inst_label].extend(inst_labels[inst_label])
    if index >= 2:
        pattern += ")".encode()

    if optional:
        pattern += ")?".encode()

    return(pattern, labels, group_number)

def parse_integer(s):
    """Parse a string as an integer, decimal, hex or binary, with optional sign"""
    assert s != None
    if s == None:
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
    labels = collections.defaultdict(list)

    inst = inst.strip()         # Remove any extra spaces and newlines
    if not inst:
        return (None, labels, group_number)

    # Split the inst into parts (mnemonic and operand)
    parts = inst.split(maxsplit=1)
    mnemonic = parts[0].lower()

    if mnemonic == '.':
        result = any_valid_instruction
        return (result, labels, group_number)

    if mnemonic == "!byte":
        result = bytearray()
        for entry in parts[1].split():
            by = parse_integer(entry)
            result += re.escape(bytearray([by]))
        return (result, labels, group_number)

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
                if len(m.group()) > 1:
                    # Record the matches if they are labels, or check the values if they are integers
                    operand_expr = m.group(1)
                    is_integer = operand_expr and (operand_expr[0] in '+-&$0123456789')
                    if is_integer:
                        operand_expr = parse_integer(operand_expr)

                    # check instruction length
                    if details.length == 2:
                        # get single byte operand
                        if is_integer:
                            result_operand += re.escape(bytearray([operand_expr]))
                        else:
                            labels[operand_expr] = [(group_number, False)]
                            result_operand += "(.)".encode()
                            group_number += 1
                    elif details.length == 3:
                        # get a two byte operand
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

    if details is None:
        raise ValueError(f"Invalid operand format: {operand}")

    if not instruction_template in opcodes:
        raise ValueError(f"Invalid operand for instruction: {instruction_template}, operand {operand}")

    opcode = opcodes[instruction_template]
    result = re.escape(bytearray([opcode]))+result_operand

    # Return the pattern, any labels defined here and the length of the instruction
    return (result, labels, group_number)

# Parse a full snippet (list of assembly lines)
def parse_snippet(program):
    # parse the program into a whole_pattern
    whole_pattern = bytearray()
    whole_labels = collections.defaultdict(list)
    group_number = 1

    for line in program.splitlines():
        pattern, labels, group_number = parse_line(line, group_number)
        if pattern:
            whole_pattern += pattern
        if labels:
            for label in labels:
                whole_labels[label].extend(labels[label])

    return Snippet(whole_pattern, whole_labels)
