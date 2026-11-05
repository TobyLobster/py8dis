"""
Main Formatter

Formats the component parts of a line of disassembly to output, for the
current assembler (config.get_assembler()). The line objects in output.py
use it, as do comment.py and classification.py.

- The comment at the end of a line of code or data:
  add_inline_comment_including_hexdump() pads the line to the inline
  comment column, then adds the hex dump (see add_hex_dump(): the line's
  binary address, its bytes and their characters, then if they're shown the
  cycle count and the CPU state, and the runtime address of moved code), and
  then the inline comments on its bytes (see inline_annotation_texts()).
  docs/configuration.md describes the settings for these.

- The formatters, each of which writes a number from the binary in its own
  way: in hex, in decimal, as a signed number, as a character, or in binary.
  Commands such as hexadecimal(), char() and binary() (see commands.py)
  choose one for an address, which is kept in the session's
  disassembly.format_hint. constant8() and constant16() write the byte or
  word at an address with its formatter (uint_formatter() by default), for
  classification.get_constant8() and get_constant16(), when there's no
  expression for it.

- format_comment(), for a word wrapped comment on lines of its own, and
  explicit_label_with_inline_comment(), for a constant's 'name = value'
  line.
"""

import config
import movemanager
import re
import textwrap
import utils
import memorymanager
import session
from memorymanager import BinaryAddr
from align import Align

def add_hex_dump(binary_addr, length, cycles_description, s, encoding=None):
    """Creates the majority of the inline comment for a line of output.

    Returns the line 's' (already padded to the inline comment column) with
    the hex dump for its 'length' bytes from binary_addr added: the comment
    prefix, then the binary address, the bytes (no more than
    config.get_hex_dump_max_bytes(), with '...' if there are more), the
    bytes as characters, the cycle count ('cycles_description', e.g. '2/3',
    or "" for data), the CPU state, and the move commentary (the runtime
    address and move ID of moved code), e.g. '; 2000: a2 00       ..'. Each
    part that's shown has a fixed width, so that they line up from line to
    line. Without config.get_hex_dump(), 's' is returned as it is.

    The characters are in the given text encoding (e.g. a string's), or
    the session's (see config.set_text_encoding()).
    """

    memory_binary = session.current().memory.binary
    assert isinstance(binary_addr, BinaryAddr)
    if not config.get_hex_dump():
        return s

    s += config.get_assembler().comment_prefix() + " "

    # Add hex characters as a fixed width string (three characters for each
    # byte, plus room for '...')
    data = memory_binary[binary_addr:binary_addr + min(length, config.get_hex_dump_max_bytes())]
    dump_hex = " ".join(utils.plainhex2(x) for x in data)
    if length > config.get_hex_dump_max_bytes():
        dump_hex += "... "
    dump_hex = utils.tab_to(dump_hex, 3 * config.get_hex_dump_max_bytes() + 3)

    # Add ASCII characters as a fixed width string (in the encoding: '.' for
    # a byte with no printable character)
    if config.get_hex_dump_show_ascii():
        import textencoding
        if encoding is None:
            encoding = textencoding.current()
        dump_chars = utils.tab_to("".join(encoding.char(x) or "." for x in data), config.get_hex_dump_max_bytes())
    else:
        dump_chars = ""

    # Add cycle counts
    if config.get_show_cycles() and cycles_description and len(cycles_description) > 0:
        # (e.g. "4 cycles", or for the 6502's JAM, "halts")
        units = " cycles" if cycles_description[0].isdigit() else ""
        cycles_description = utils.tab_to(" " + cycles_description + units, 14)
    else:
        cycles_description = ""

    # Add CPU state as a fixed width string (what's known about the registers
    # and flags after the instruction, see cpu.calculate_cpu_states(); blank
    # where there's none, e.g. for data)
    dump_cpu_state = ""
    if config.get_show_cpu_state():
        state = session.current().cpu.cpu_states[binary_addr]
        if state:
            dump_cpu_state = " " + state.show()
        dump_cpu_state = utils.tab_to(dump_cpu_state, 22)

    # Add move commentary, as a fixed width string: for code or data that
    # runs somewhere else (see move()), its runtime address and move ID, e.g.
    # ' :0900[1]'. (There's no column for it if there are no moves.)
    runtime_addr = movemanager.b2r(binary_addr)
    dump_move = ""
    if movemanager.has_any_moves():
        if runtime_addr != binary_addr:
            dump_move = " :%s[%d]" % (utils.plainhex4(runtime_addr), session.current().moves.move_id_for_binary_addr[binary_addr])
        dump_move = utils.tab_to(dump_move, 12)

    # Join them all together: address, hex bytes, characters, cpu state, move details
    s += utils.plainhex4(binary_addr) + ": " + dump_hex + dump_chars + cycles_description + dump_cpu_state + dump_move
    return s

def add_inline_comment_including_hexdump(binary_loc, length, cycles_description, annotations, s, encoding=None):
    """Creates the entire inline comment for the line as a string.

    Returns the line 's' (e.g. '    lda #3'), for the 'length' bytes at
    binary_loc, padded to the inline comment column, with the hex dump (see
    add_hex_dump(), which says what 'cycles_description' and 'encoding' are)
    and any inline annotations on its bytes (e.g. a comment given with
    comment(..., inline=True)) from 'annotations' (the session's, see
    disassembly.py, or None for none). Spaces at the end are taken off.
    """
    assert isinstance(binary_loc, movemanager.BinaryLocation)

    binary_loc = movemanager.make_binloc(binary_loc)

    assert isinstance(binary_loc.binary_addr, BinaryAddr)
    # Add spaces up to the comment column
    s = utils.tab_to(s, config.get_inline_comment_column())

    # Add any hex dump (fixed width)
    s = add_hex_dump(binary_loc.binary_addr, length, cycles_description, s, encoding)

    # Add any inline annotations
    for text in inline_annotation_texts(binary_loc, length, annotations):
        # Make sure the comment is separated from what comes before
        # (e.g. a full width ASCII dump column, which has no padding
        # after it when there are no moves). Each annotation's text has
        # its own comment prefix.
        if text and not s.endswith(" "):
            s += " "
        s += text
    return s.rstrip()

def inline_annotation_texts(binary_loc, length, annotations):
    """The text of each inline annotation (e.g. an inline comment) for the
    'length' bytes starting at binary_loc, in the order they're output: for
    each byte in turn, sorted (see utils.sorted_annotations()). 'annotations'
    is the session's (see disassembly.py), or None or empty for none.

    (Getting an annotation's text formats it, naming any labels in it, the
    first time. See output.Instruction.resolve().)"""

    result = []
    if annotations:
        for i in range(0, length):
            for annotation in utils.sorted_annotations(binary_loc, annotations[binary_loc]):
                if annotation.align == Align.INLINE:
                    result.append(annotation.as_string(binary_loc.binary_addr))
            binary_loc = movemanager.BinaryLocation(binary_loc.binary_addr + 1, binary_loc.move_id)
    return result

def uhex_formatter(n, bits, pad=False):
    """Format an 8 or 16 bit number as hex, with two or four digits (see
    Assembler.hex2() and hex4()). 'pad' isn't used. (For uhex().)
    """

    assert bits in (8, 16)
    assert 0 <= n < (1<<bits)
    if bits == 8:
        return config.get_assembler().hex2(n)
    return config.get_assembler().hex4(n)

def uint_formatter(n, bits, pad=False):
    """Format an 8 or 16 bit number as hex or single digit decimal.

    For readability we format values 0-9 as decimal, but use hex
    otherwise. Includes optional left padding to align columns of data
    in blocks: with 'pad', a decimal digit is padded to the width of a hex
    number (for padded_uint()).

    This is the default formatter, for data without one of its own (see
    constant()), and the one uint() gives.
    """

    assert bits in (8, 16)
    assert 0 <= n < (1<<bits)
    if n < 10:
        s = "%d" % n
        if pad:
            # (To the width of a hex number, e.g. '$12' or '$1234')
            assembler = config.get_assembler()
            s = s.rjust(len(assembler.hex2(0) if bits == 8 else assembler.hex4(0)))
        return s
    if bits == 8:
        return config.get_assembler().hex2(n)
    return config.get_assembler().hex4(n)

def uint_no_hex_formatter(n, bits, pad=False):
    """Format an 8 or 16 bit number as an unsigned decimal. With 'pad', it's
    padded on the left to 3 characters (8 bit) or 5 (16 bit). (For
    uint_no_hex(), which doesn't pad.)
    """

    assert bits in (8, 16)
    assert 0 <= n < (1<<bits)
    s = "%d" % n
    if pad:
        s = ("    " + s)[-3 if bits == 8 else -5:]
    return s

def sint_formatter(n, bits):
    """Format an 8 or 16 bit number as a signed decimal (e.g. -2 for the
    byte $fe), if the assembler supports signed integers (see
    Assembler.supports_signed_integers()), otherwise as an unsigned decimal.
    (For sint().)"""
    assert bits in (8, 16)
    assert 0 <= n < (1<<bits)

    if config.get_assembler().supports_signed_integers():
        if bits == 8:
            signedn = n if n < 128 else n-256
        elif bits == 16:
            signedn = n if n < 32768 else n-65536

        s = "%d" % signedn
        return s
    return str(n)

def char_formatter(n, bits):
    """Format a quoted character.

    Returns a quoted character if possible otherwise just a hex or
    decimal integer (as uint_formatter()). The character is in the
    session's text encoding (see Assembler.encoded_char_literal()). (For
    char().)
    """

    import textencoding
    c = config.get_assembler().encoded_char_literal(n, textencoding.current())
    if c is not None:
        return c
    return uint_formatter(n, bits)

def binary_formatter(n, bits):
    """Format a binary string

    Pads to the number of bits given, with leading zeroes, in the
    assembler's syntax (e.g. '%00101100'). (For binary().)
    """

    s = bin(n)[2:]
    s = ("0"*bits + s)[-bits:]
    return config.get_assembler().binary_format(s)

def picture_binary_formatter(n, bits):
    """Format 'picture' binary data.

    'Picture' binary uses alternative characters for expressing binary
    digits. This is most commonly used for displaying 1-bit per pixel
    sprites. (e.g. acme's '%..#.##..'. For an assembler without it, it's
    the same as binary_formatter(): see Assembler.picture_binary().) (For
    picture_binary().)
    """

    return config.get_assembler().picture_binary(binary_formatter(n, bits))

def decimal_formatter(n, bits):
    """Format a regular decimal number (For decimal().)"""

    return "%d" % n

def hexadecimal_formatter(n, bits):
    """Format an 8 or 16 bit hex number: two digits for a value up to $ff,
    otherwise four (see Assembler.hex()), whatever 'bits' is. (For
    hexadecimal().)"""

    return config.get_assembler().hex(n)

def constant(binary_addr, n, bits):
    """Format a constant value, using whatever formatter is hinted

    'n' is the value at binary_addr ('bits' is 8 for a byte, or 16 for a
    word), and the formatter is the one given for binary_addr (see e.g.
    hexadecimal() in commands.py), or uint_formatter() if there isn't one."""

    format_hint = session.current().disassembly.format_hint.get(binary_addr, uint_formatter)
    return format_hint(n, bits)

def constant8(binary_addr):
    """Format a constant value, using whatever formatter is hinted: the
    byte at binary_addr (see constant())."""

    memory_binary = session.current().memory.binary
    assert memorymanager.is_valid_binary_addr(binary_addr)
    n = memory_binary[binary_addr]
    return constant(binary_addr, n, 8)

def constant16(binary_addr):
    """Format a constant value, using whatever formatter is hinted: the
    word (low byte first) at binary_addr (see constant())."""

    assert memorymanager.is_valid_binary_addr(binary_addr)
    n = memorymanager.get_u16_binary(binary_addr)
    return constant(binary_addr, n, 16)

def format_comment(text, indent):
    """Format a standalone (i.e. not inline) multiline comment.

    Text is word wrapped, at config.get_word_wrap_comment_column(). Each
    line starts with the indent ('indent' levels) and the comment prefix.
    Each paragraph of the text (each line of it) is wrapped separately. A
    paragraph that starts with spaces keeps them on its wrapped lines, which
    also line up after a 'name: ' at its start (e.g. a subroutine header's
    '    A: the value'). Returns the lines as one string, with newlines
    between them.
    """

    prefix = config.get_indent_string() * indent + config.get_assembler().comment_prefix() + " "
    text_width = config.get_word_wrap_comment_column() - len(prefix)
    result = ""
    for paragraph in text.split("\n"):
        m = re.match(r"(\s+)(\S+: )?", paragraph)
        hanging_indent = m.group(1) + " " * len(m.group(2) or "") if m else ""
        if len(hanging_indent) > text_width // 2:
            hanging_indent = ""
        result += "\n".join([prefix + line for line in textwrap.fill(paragraph, text_width, subsequent_indent=hanging_indent).split("\n")]) + "\n"
    return result[:-1]

def explicit_label_with_inline_comment(name, value, offset=None, align_value_column=0, inline_comment=None, align_comment_column=0):
    """Format an explicit 'label=value' line, including an optional inline comment

    The line is the assembler's explicit_label() (with the name padded to
    'align_value_column'), then the comment, if any, at
    'align_comment_column'. (For the constants, see
    output.ConstantDefinition.)"""

    result = config.get_assembler().explicit_label(name, value, offset=offset, align_column=align_value_column)
    if inline_comment:
        # Add spaces up to the alignment column
        result = utils.tab_to(result, align_comment_column)

        # Add inline comment itself
        result += config.get_assembler().comment_prefix() + " " + inline_comment
    return result
