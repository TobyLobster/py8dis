#!/usr/bin/env python3
"""
Tests for rendering output lines (see py8dis/output.py), run by run_tests.py -c.

Each test makes one line object (an instruction, a block of data, a comment,
a directive...) and checks the text it renders for each assembler, without
running a disassembly. A few bytes of memory are set up for the hex dumps
and the data; label operands are plain names, since naming labels isn't
part of rendering.

Usage: ./render_tests.py          check every test (exits with 1 if any fail)
       ./render_tests.py --print  print what each test renders now, in the
                                  form used in EXPECTED below
"""

import os
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"

ASSEMBLERS_6502 = ["acme", "beebasm", "xa", "64tass", "ca65"]
ASSEMBLERS_Z80 = ["z88dk", "sjasmplus"]

# The bytes at &2000 onwards: 'lda #&41' (with 'A' as a character), 'lda
# (&70),y', 'lda &0070' (absolute, with a zero page operand), 'rts', some
# data (including a byte that isn't printable), and the string "Hi!" then 13
MEMORY = [0xa9, 0x41, 0xb1, 0x70, 0xad, 0x70, 0x00, 0x60,
          0x01, 0x02, 0x03, 0xff, 0x34, 0x12, 0x78, 0x56,
          0x48, 0x69, 0x21, 0x0d]

def binary_loc(addr):
    import movemanager
    import memorymanager
    return movemanager.BinaryLocation(memorymanager.BinaryAddr(addr), movemanager.BASE_MOVE_ID)

def instruction(addr, length, *args, **kwargs):
    """An output.Instruction placed at addr (with no extra indent, cycle count
    or inline comments)."""
    import output
    return output.Instruction(*args, **kwargs).placed(binary_loc(addr), length, 0, "", None)

def with_cpu_state(cpu_name, make_line):
    """Make the line with config.set_show_cpu_state(True), with the CPU state
    after the instruction at &2000 worked out as when tracing: the CPU
    updates an unknown state for it. For the 6502 that's 'lda #&41', so A=&41
    and the N and Z flags are clear. For the 8080 the instruction is changed
    to 'mvi a, $41' (&3e &41), so A=&41 and nothing else is known."""
    def make():
        import config
        import cpu6502
        import cpu8080
        import memorymanager
        import session
        config.set_show_cpu_state(True)
        cpu = cpu6502.Cpu6502() if cpu_name == "6502" else cpu8080.Cpu8080()
        session.current().cpu = cpu
        if cpu_name == "8080":
            session.current().memory.binary[0x2000] = 0x3e
        state = cpu.CpuState()
        cpu.opcodes[session.current().memory.binary[0x2000]].update_cpu_state(memorymanager.BinaryAddr(0x2000), state)
        cpu.cpu_states[0x2000] = state
        return make_line()
    return make

def with_cycles(cpu_name, addr):
    """The instruction at addr as the CPU makes it (see its opcode's
    as_lines()), with config.set_show_cycles(True), so that the cycles come
    from the CPU's own table. (Only for instructions without an address,
    since naming labels isn't part of rendering.)"""
    def make():
        import config
        import cpu6502
        import cpu8080
        import session
        config.set_show_cycles(True)
        cpu = cpu6502.Cpu6502() if cpu_name == "6502" else cpu8080.Cpu8080()
        session.current().cpu = cpu
        return cpu.opcodes[MEMORY[addr - 0x2000]].as_lines(binary_loc(addr), None)[0]
    return make

def with_6510(opcode_bytes, show_cycles=False):
    """The instruction made by the 6510 CPU (the 6502 with its undocumented
    opcodes) for the given bytes at &2000, as when disassembling. (Only for
    instructions without an address, since naming labels isn't part of
    rendering.)"""
    def make():
        import config
        import cpu6510
        import session
        config.set_show_cycles(show_cycles)
        cpu = cpu6510.Cpu6510()
        session.current().cpu = cpu
        session.current().memory.binary[0x2000:0x2000 + len(opcode_bytes)] = opcode_bytes
        return cpu.opcodes[opcode_bytes[0]].as_lines(binary_loc(0x2000), None)[0]
    return make

def with_z80(opcode_bytes, show_cycles=False, show_cpu_state=False):
    """The instruction made by the Z80 CPU for the given bytes at &2000, as
    when disassembling, with the CPU state it leaves if 'show_cpu_state'
    (starting with nothing known). (Only for instructions without an address,
    since naming labels isn't part of rendering.)"""
    def make():
        import config
        import cpuz80
        import memorymanager
        import session
        config.set_show_cycles(show_cycles)
        config.set_show_cpu_state(show_cpu_state)
        cpu = cpuz80.CpuZ80()
        session.current().cpu = cpu
        session.current().memory.binary[0x2000:0x2000 + len(opcode_bytes)] = opcode_bytes
        opcode = cpu.opcode_at(0x2000)
        if show_cpu_state:
            state = cpu.CpuState()
            opcode.update_cpu_state(memorymanager.BinaryAddr(0x2000), state)
            cpu.cpu_states[0x2000] = state
        return opcode.as_lines(binary_loc(0x2000), None)[0]
    return make

def undocumented_zp():
    """'lax (ptr),y' (&b3), written as data bytes with a one-byte operand"""
    import expression
    import output
    line = instruction(0x2000, 2, "lax", expression.Name("ptr"), prefix="(", suffix="),y", form=output.Instruction.UNDOCUMENTED,
                       data_byte=expression.Num(0xb3, "hex2"))
    line.operand_length = 1
    return line

def text_string(text_bytes, encoding_name, session_encoding=None):
    """A string of the given bytes at &2010, in the given text encoding
    (with config.set_text_encoding(session_encoding) if given, which the hex
    dump uses)"""
    def make():
        import config
        import output
        import session
        import textencoding
        if session_encoding is not None:
            config.set_text_encoding(session_encoding)
        session.current().memory.binary[0x2010:0x2010 + len(text_bytes)] = text_bytes
        return output.StringData(binary_loc(0x2010), len(text_bytes), None, textencoding.get(encoding_name))
    return make

def data_with_text_encoding(encoding_name):
    """The byte data at &2010 (the string "Hi!" then 13 in ASCII), with
    config.set_text_encoding(encoding_name), which the hex dump uses"""
    def make():
        import config
        import output
        config.set_text_encoding(encoding_name)
        return output.DataBlock(binary_loc(0x2010), 4, None, 1, None)
    return make

class MultiLine:
    """Several lines, rendered one after the other"""
    def __init__(self, *lines):
        self.lines = lines
    def render(self):
        return [text for line in self.lines for text in line.render()]

def with_assertions():
    """The end of the output, with assertions: a name's value, a negative
    value (written e.g. '-$36'), and one that uses the current address
    ('$'), which is left out, since it would be checked at the end"""
    import config
    import output
    config.get_assembler().assert_expr("table", 0x1234)
    config.get_assembler().assert_expr("flags - err_nr", -0x36)
    config.get_assembler().assert_expr("target - $", 3)
    return output.Directive("disassembly_end")

# "Hello", '"', 13 in PETSCII (shifted H), and "@ab[" in screen codes
PETSCII_HELLO = [0xc8, 0x45, 0x4c, 0x4c, 0x4f, 0x22, 0x0d]
SCREEN_TEXT = [0x00, 0x01, 0x02, 0x1b]

def make_tests():
    """The tests: a list of (name, assemblers, function making the line).

    Tests whose name ends with '*' are also checked with upper case output."""
    import config
    import expression
    import output
    import session
    Instruction = output.Instruction
    Name = expression.Name
    Num = expression.Num

    return [
        ("implied *",
         ASSEMBLERS_6502, lambda: instruction(0x2007, 1, "rts")),
        ("immediate with a character",
         ASSEMBLERS_6502, lambda: instruction(0x2000, 2, "lda", Num(0x41, "hex"), prefix="#", char_literal="'A'")),
        ("operand prefix and suffix *",
         ASSEMBLERS_6502, lambda: instruction(0x2002, 2, "lda", Name("ptr"), prefix="(", suffix="),y")),
        ("operand expression",
         ASSEMBLERS_6502, lambda: instruction(0x2002, 2, "lda", expression.Binary(Name("ptr"), "+", Num(1)))),
        ("force absolute addressing",
         ["acme", "xa", "64tass", "ca65"], lambda: instruction(0x2004, 3, "lda", Name("zp_value"), form=Instruction.FORCE_ABSOLUTE)),
        ("force absolute addressing, indexed *",
         ["acme", "xa", "64tass", "ca65"], lambda: instruction(0x2004, 3, "lda", Name("zp_value"), suffix=",x", form=Instruction.FORCE_ABSOLUTE)),
        ("absolute addressing as data *",
         ["beebasm"], lambda: instruction(0x2004, 3, "lda", Name("zp_value"), suffix=",x", form=Instruction.AS_DATA,
                                          data_byte=Num(0xad, "hex"), listing_operand=Name("zp_value"))),
        ("8080 instruction",
         ["z88dk-8080"], lambda: instruction(0x2000, 2, "mvi a,", Num(0x41, "hex"), char_literal="'A'")),
        ("8080 undocumented opcode *",
         ["z88dk-8080"], lambda: instruction(0x2000, 3, "jmp", Name("finish"), form=Instruction.UNDOCUMENTED, data_byte=Num(0xcb, "hex2"))),
        ("8080 undocumented opcode, no operand",
         ["z88dk-8080"], lambda: instruction(0x2000, 1, "nop", form=Instruction.UNDOCUMENTED, data_byte=Num(0x08, "hex2"))),
        ("Z80 instruction *",
         ASSEMBLERS_Z80, with_z80([0xdd, 0x36, 0xfd, 0x41])),
        ("Z80 instruction, prefix and displacement before the opcode",
         ASSEMBLERS_Z80, with_z80([0xfd, 0xcb, 0x7f, 0x46])),
        ("Z80 undocumented opcode that's assembled *",
         ASSEMBLERS_Z80, with_z80([0xdd, 0x67])),
        ("Z80 undocumented opcode that's assembled, copying to a register",
         ASSEMBLERS_Z80, with_z80([0xdd, 0xcb, 0x02, 0x00])),
        ("Z80 undocumented opcode as data *",
         ASSEMBLERS_Z80, with_z80([0xed, 0x4c])),
        ("Z80 undocumented opcode as data, with a displacement",
         ASSEMBLERS_Z80, with_z80([0xdd, 0xcb, 0xfe, 0x41])),
        ("Z80 prefix with no effect",
         ASSEMBLERS_Z80, with_z80([0xdd, 0x00])),
        ("Z80 CPU state",
         ASSEMBLERS_Z80, with_z80([0xdd, 0x21, 0x34, 0x12], show_cpu_state=True)),
        ("Z80 CPU state, flags",
         ASSEMBLERS_Z80, with_z80([0xaf], show_cpu_state=True)),
        ("Z80 cycles",
         ASSEMBLERS_Z80, with_z80([0xed, 0xb0], show_cycles=True)),
        ("6502 CPU state",
         ASSEMBLERS_6502, with_cpu_state("6502", lambda: instruction(0x2000, 2, "lda", Num(0x41, "hex"), prefix="#"))),
        ("8080 CPU state",
         ["z88dk-8080"], with_cpu_state("8080", lambda: instruction(0x2000, 2, "mvi a,", Num(0x41, "hex")))),
        ("6502 cycles",
         ["beebasm"], with_cycles("6502", 0x2000)),
        ("8080 cycles",
         ["z88dk-8080"], with_cycles("8080", 0x2000)),
        ("8080 cycles, memory",
         ["z88dk-8080"], with_cycles("8080", 0x2003)),
        ("byte data *",
         ASSEMBLERS_6502 + ["z88dk-8080", "sjasmplus"], lambda: output.DataBlock(binary_loc(0x2008), 4, None, 1, None)),
        ("byte data, two per line",
         ASSEMBLERS_6502, lambda: output.DataBlock(binary_loc(0x2008), 4, 2, 1, None)),
        ("word data",
         ASSEMBLERS_6502 + ["z88dk-8080", "sjasmplus"], lambda: output.DataBlock(binary_loc(0x200c), 4, None, 2, None)),
        ("string *",
         ASSEMBLERS_6502, lambda: output.StringData(binary_loc(0x2010), 4, None)),
        ("ASCII string with a quote *",
         ASSEMBLERS_6502, text_string([0x48, 0x22, 0x69, 0x22], "ascii")),
        ("operand with a low byte in an expression",
         ASSEMBLERS_6502, lambda: instruction(0x2000, 2, "lda", expression.Binary(expression.Unary("<", Name("table")), "+", Num(1)), prefix="#")),
        ("PETSCII string *",
         ASSEMBLERS_6502, text_string(PETSCII_HELLO, "petscii", "petscii")),
        ("screen code string *",
         ASSEMBLERS_6502, text_string(SCREEN_TEXT, "screen")),
        ("ASCII string with PETSCII the session's encoding",
         ASSEMBLERS_6502, text_string([0x48, 0x69, 0x21, 0x0d], "ascii", "petscii")),
        ("PETSCII string over two lines",
         ["beebasm"], text_string(PETSCII_HELLO * 2, "petscii", "petscii")),
        ("byte data with PETSCII the session's encoding",
         ASSEMBLERS_6502, data_with_text_encoding("petscii")),
        ("blank",
         ASSEMBLERS_6502, lambda: output.Blank()),
        ("one line comment",
         ASSEMBLERS_6502 + ["z88dk-8080", "sjasmplus"], lambda: output.CommentLine("Memory locations")),
        ("empty one line comment",
         ASSEMBLERS_6502, lambda: output.CommentLine("")),
        ("word wrapped comment",
         ASSEMBLERS_6502, lambda: output.Comment("This is a long comment which is word wrapped, since it is much too long to fit on one line of the output.", 1)),
        ("constant definition *",
         ASSEMBLERS_6502 + ["z88dk-8080", "sjasmplus"], lambda: output.ConstantDefinition("lives", "3", 12, "Starting number of lives", 24)),
        ("code start *",
         ASSEMBLERS_6502 + ["z88dk-8080", "sjasmplus"], lambda: output.Directive("code_start", 0x2000, 0x2014, True)),
        ("code start, after other code *",
         ["xa", "ca65", "sjasmplus"], lambda: output.Directive("code_start", 0x3000, 0x3010, False)),
        ("include binary file *",
         ASSEMBLERS_6502 + ASSEMBLERS_Z80, lambda: output.Directive("include_binary_file", "data.bin")),
        ("6510 undocumented opcode, immediate *",
         ASSEMBLERS_6502, with_6510([0x0b, 0x81])),
        ("6510 ALR, which acme calls ASR",
         ASSEMBLERS_6502, with_6510([0x4b, 0x0f])),
        ("6510 LXA, which ca65 calls LAX",
         ["acme", "64tass", "ca65"], with_6510([0xab, 0x12])),
        ("6510 SBX, which ca65 calls AXS",
         ["acme", "64tass", "ca65"], with_6510([0xcb, 0x12])),
        ("6510 undocumented opcode acme doesn't use",
         ASSEMBLERS_6502, with_6510([0x2b, 0x81])),
        ("6510 undocumented opcode, implied",
         ASSEMBLERS_6502, with_6510([0x1a])),
        ("6510 JAM, with cycles",
         ASSEMBLERS_6502, with_6510([0x02], show_cycles=True)),
        ("6510 undocumented opcode as data, zero page operand *",
         ["beebasm", "xa"], undocumented_zp),
        ("start, for the 6510 *",
         ["acme", "64tass", "ca65"], lambda: (setattr(session.current(), "cpu", __import__("cpu6510").Cpu6510()), output.Directive("disassembly_start"))[1]),
        ("start, for the 65C02 *",
         ["acme", "64tass", "ca65"], lambda: (config.set_cmos(True), output.Directive("disassembly_start"))[1]),
        ("Z80 operand with low and high bytes *",
         ASSEMBLERS_Z80, lambda: instruction(0x2000, 2, "ld a,", expression.Binary(expression.Unary("<", Name("table")), "+", expression.Unary(">", Name("table"))))),
        ("Z80 character literals",
         ASSEMBLERS_Z80, lambda: instruction(0x2000, 2, "ld a,", expression.Binary(expression.Binary(Num(0x27, "char"), "+", Num(0x5c, "char")), "+", Num(0x22, "char")))),
        ("move start and end *",
         ASSEMBLERS_Z80, lambda: MultiLine(output.Directive("pseudopc_start", 0x8000, 0x2000, 0x10, 1), output.Directive("pseudopc_end", 0x8000, 0x2000, 0x10, 1))),
        ("start *",
         ["sjasmplus"], lambda: output.Directive("disassembly_start")),
        ("end, with assertions *",
         ASSEMBLERS_Z80, with_assertions),
        ("end, saving to a file *",
         ["acme", "beebasm"], lambda: (setattr(session.current(), "output_filename", "Out.bin"), output.Directive("disassembly_end"))[1]),
    ]

# What each test should render, for each assembler (one string per line of
# output). Made with --print, and checked by hand.
EXPECTED = {
    'implied, acme': [
        '    rts                                                               ; 2007: 60          `',
    ],
    'implied, acme, upper case': [
        '    RTS                                                               ; 2007: 60          `',
    ],
    'implied, beebasm': [
        '    rts                                                               ; 2007: 60          `',
    ],
    'implied, beebasm, upper case': [
        '    RTS                                                               ; 2007: 60          `',
    ],
    'implied, xa': [
        '    rts                                                               // 2007: 60          `',
    ],
    'implied, xa, upper case': [
        '    RTS                                                               // 2007: 60          `',
    ],
    'implied, 64tass': [
        '    rts                                                               ; 2007: 60          `',
    ],
    'implied, 64tass, upper case': [
        '    RTS                                                               ; 2007: 60          `',
    ],
    'implied, ca65': [
        '    rts                                                               ; 2007: 60          `',
    ],
    'implied, ca65, upper case': [
        '    RTS                                                               ; 2007: 60          `',
    ],
    'immediate with a character, acme': [
        "    lda #$41 ; 'A'                                                    ; 2000: a9 41       .A",
    ],
    'immediate with a character, beebasm': [
        "    lda #&41 ; 'A'                                                    ; 2000: a9 41       .A",
    ],
    'immediate with a character, xa': [
        "    lda #$41 // 'A'                                                   // 2000: a9 41       .A",
    ],
    'immediate with a character, 64tass': [
        "    lda #$41 ; 'A'                                                    ; 2000: a9 41       .A",
    ],
    'immediate with a character, ca65': [
        "    lda #$41 ; 'A'                                                    ; 2000: a9 41       .A",
    ],
    'operand prefix and suffix, acme': [
        '    lda (ptr),y                                                       ; 2002: b1 70       .p',
    ],
    'operand prefix and suffix, acme, upper case': [
        '    LDA (ptr),Y                                                       ; 2002: B1 70       .p',
    ],
    'operand prefix and suffix, beebasm': [
        '    lda (ptr),y                                                       ; 2002: b1 70       .p',
    ],
    'operand prefix and suffix, beebasm, upper case': [
        '    LDA (ptr),Y                                                       ; 2002: B1 70       .p',
    ],
    'operand prefix and suffix, xa': [
        '    lda (ptr),y                                                       // 2002: b1 70       .p',
    ],
    'operand prefix and suffix, xa, upper case': [
        '    LDA (ptr),Y                                                       // 2002: B1 70       .p',
    ],
    'operand prefix and suffix, 64tass': [
        '    lda (ptr),y                                                       ; 2002: b1 70       .p',
    ],
    'operand prefix and suffix, 64tass, upper case': [
        '    LDA (ptr),Y                                                       ; 2002: B1 70       .p',
    ],
    'operand prefix and suffix, ca65': [
        '    lda (ptr),y                                                       ; 2002: b1 70       .p',
    ],
    'operand prefix and suffix, ca65, upper case': [
        '    LDA (ptr),Y                                                       ; 2002: B1 70       .p',
    ],
    'operand expression, acme': [
        '    lda ptr + 1                                                       ; 2002: b1 70       .p',
    ],
    'operand expression, beebasm': [
        '    lda ptr + 1                                                       ; 2002: b1 70       .p',
    ],
    'operand expression, xa': [
        '    lda ptr + 1                                                       // 2002: b1 70       .p',
    ],
    'operand expression, 64tass': [
        '    lda ptr + 1                                                       ; 2002: b1 70       .p',
    ],
    'operand expression, ca65': [
        '    lda ptr + 1                                                       ; 2002: b1 70       .p',
    ],
    'force absolute addressing, acme': [
        '    lda+2 zp_value                                                    ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, xa': [
        '    lda !zp_value                                                     // 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, 64tass': [
        '    lda @w zp_value                                                   ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, ca65': [
        '    lda a:zp_value                                                    ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, indexed, acme': [
        '    lda+2 zp_value,x                                                  ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, indexed, acme, upper case': [
        '    LDA+2 zp_value,X                                                  ; 2004: AD 70 00    .p.',
    ],
    'force absolute addressing, indexed, xa': [
        '    lda !zp_value,x                                                   // 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, indexed, xa, upper case': [
        '    LDA !zp_value,X                                                   // 2004: AD 70 00    .p.',
    ],
    'force absolute addressing, indexed, 64tass': [
        '    lda @w zp_value,x                                                 ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, indexed, 64tass, upper case': [
        '    LDA @W zp_value,X                                                 ; 2004: AD 70 00    .p.',
    ],
    'force absolute addressing, indexed, ca65': [
        '    lda a:zp_value,x                                                  ; 2004: ad 70 00    .p.',
    ],
    'force absolute addressing, indexed, ca65, upper case': [
        '    LDA A:zp_value,X                                                  ; 2004: AD 70 00    .p.',
    ],
    'absolute addressing as data, beebasm': [
        '    equb &ad, <(zp_value), >(zp_value) ; lda+2 zp_value,x             ; 2004: ad 70 00    .p.',
    ],
    'absolute addressing as data, beebasm, upper case': [
        '    EQUB &AD, <(zp_value), >(zp_value) ; LDA+2 zp_value,X             ; 2004: AD 70 00    .p.',
    ],
    '8080 instruction, z88dk-8080': [
        "    mvi a, $41 ; 'A'                                                  ; 2000: a9 41       .A",
    ],
    '8080 undocumented opcode, z88dk-8080': [
        '    db $cb, finish & $ff, finish >> 8 ; jmp finish (undocumented)     ; 2000: a9 41 b1    .A.',
    ],
    '8080 undocumented opcode, z88dk-8080, upper case': [
        '    DB $CB, finish & $FF, finish >> 8 ; JMP finish (undocumented)     ; 2000: A9 41 B1    .A.',
    ],
    '8080 undocumented opcode, no operand, z88dk-8080': [
        '    db $08 ; nop (undocumented)                                       ; 2000: a9          .',
    ],
    'Z80 instruction, z88dk': [
        '    ld (ix-3),$41                                                     ; 2000: dd 36 fd... .6.',
    ],
    'Z80 instruction, z88dk, upper case': [
        '    LD (IX-3),$41                                                     ; 2000: DD 36 FD... .6.',
    ],
    'Z80 instruction, sjasmplus': [
        '    ld (ix-3),$41                                                     ; 2000: dd 36 fd... .6.',
    ],
    'Z80 instruction, sjasmplus, upper case': [
        '    LD (IX-3),$41                                                     ; 2000: DD 36 FD... .6.',
    ],
    'Z80 instruction, prefix and displacement before the opcode, z88dk': [
        '    bit 0,(iy+127)                                                    ; 2000: fd cb 7f... ...',
    ],
    'Z80 instruction, prefix and displacement before the opcode, sjasmplus': [
        '    bit 0,(iy+127)                                                    ; 2000: fd cb 7f... ...',
    ],
    "Z80 undocumented opcode that's assembled, z88dk": [
        '    ld ixh,a                                                          ; 2000: dd 67       .g',
    ],
    "Z80 undocumented opcode that's assembled, z88dk, upper case": [
        '    LD IXH,A                                                          ; 2000: DD 67       .g',
    ],
    "Z80 undocumented opcode that's assembled, sjasmplus": [
        '    ld ixh,a                                                          ; 2000: dd 67       .g',
    ],
    "Z80 undocumented opcode that's assembled, sjasmplus, upper case": [
        '    LD IXH,A                                                          ; 2000: DD 67       .g',
    ],
    "Z80 undocumented opcode that's assembled, copying to a register, z88dk": [
        '    rlc (ix+2),b                                                      ; 2000: dd cb 02... ...',
    ],
    "Z80 undocumented opcode that's assembled, copying to a register, sjasmplus": [
        '    rlc (ix+2),b                                                      ; 2000: dd cb 02... ...',
    ],
    'Z80 undocumented opcode as data, z88dk': [
        '    db $ed, $4c ; neg (undocumented)                                  ; 2000: ed 4c       .L',
    ],
    'Z80 undocumented opcode as data, z88dk, upper case': [
        '    DB $ED, $4C ; NEG (undocumented)                                  ; 2000: ED 4C       .L',
    ],
    'Z80 undocumented opcode as data, sjasmplus': [
        '    db $ed, $4c ; neg (undocumented)                                  ; 2000: ed 4c       .L',
    ],
    'Z80 undocumented opcode as data, sjasmplus, upper case': [
        '    DB $ED, $4C ; NEG (undocumented)                                  ; 2000: ED 4C       .L',
    ],
    'Z80 undocumented opcode as data, with a displacement, z88dk': [
        '    db $dd, $cb, -2, $41 ; bit 0,(ix-2) (undocumented)                ; 2000: dd cb fe... ...',
    ],
    'Z80 undocumented opcode as data, with a displacement, sjasmplus': [
        '    db $dd, $cb, -2, $41 ; bit 0,(ix-2) (undocumented)                ; 2000: dd cb fe... ...',
    ],
    'Z80 prefix with no effect, z88dk': [
        '    db $dd ; prefix with no effect (undocumented)                     ; 2000: dd          .',
    ],
    'Z80 prefix with no effect, sjasmplus': [
        '    db $dd ; prefix with no effect (undocumented)                     ; 2000: dd          .',
    ],
    'Z80 CPU state, z88dk': [
        '    ld ix,$1234                                                       ; 2000: dd 21 34... .!4 A:-- BC:---- DE:---- HL:---- IX:1234 IY:---- SP:---- ------',
    ],
    'Z80 CPU state, sjasmplus': [
        '    ld ix,$1234                                                       ; 2000: dd 21 34... .!4 A:-- BC:---- DE:---- HL:---- IX:1234 IY:---- SP:---- ------',
    ],
    'Z80 CPU state, flags, z88dk': [
        '    xor a                                                             ; 2000: af          .   A:00 BC:---- DE:---- HL:---- IX:---- IY:---- SP:---- sZhPnc',
    ],
    'Z80 CPU state, flags, sjasmplus': [
        '    xor a                                                             ; 2000: af          .   A:00 BC:---- DE:---- HL:---- IX:---- IY:---- SP:---- sZhPnc',
    ],
    'Z80 cycles, z88dk': [
        '    ldir                                                              ; 2000: ed b0       ..  16/21 cycles',
    ],
    'Z80 cycles, sjasmplus': [
        '    ldir                                                              ; 2000: ed b0       ..  16/21 cycles',
    ],
    '6502 CPU state, acme': [
        '    lda #$41                                                          ; 2000: a9 41       .A  A:41 X:-- Y:-- n---z-',
    ],
    '6502 CPU state, beebasm': [
        '    lda #&41                                                          ; 2000: a9 41       .A  A:41 X:-- Y:-- n---z-',
    ],
    '6502 CPU state, xa': [
        '    lda #$41                                                          // 2000: a9 41       .A  A:41 X:-- Y:-- n---z-',
    ],
    '6502 CPU state, 64tass': [
        '    lda #$41                                                          ; 2000: a9 41       .A  A:41 X:-- Y:-- n---z-',
    ],
    '6502 CPU state, ca65': [
        '    lda #$41                                                          ; 2000: a9 41       .A  A:41 X:-- Y:-- n---z-',
    ],
    '8080 CPU state, z88dk-8080': [
        '    mvi a, $41                                                        ; 2000: 3e 41       >A  A:41 B:-- C:-- D:-- E:-- H:-- L:-- SP:---- -----',
    ],
    '6502 cycles, beebasm': [
        "    lda #&41 ; 'A'                                                    ; 2000: a9 41       .A  2 cycles",
    ],
    '8080 cycles, z88dk-8080': [
        '    xra c                                                             ; 2000: a9          .   4 cycles',
    ],
    '8080 cycles, memory, z88dk-8080': [
        '    mov m, b                                                          ; 2003: 70          p   7 cycles',
    ],
    'byte data, acme': [
        '    !byte 1, 2, 3, $ff                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, acme, upper case': [
        '    !BYTE 1, 2, 3, $FF                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, beebasm': [
        '    equb 1, 2, 3, &ff                                                 ; 2008: 01 02 03... ...',
    ],
    'byte data, beebasm, upper case': [
        '    EQUB 1, 2, 3, &FF                                                 ; 2008: 01 02 03... ...',
    ],
    'byte data, xa': [
        '    .byt 1, 2, 3, $ff                                                 // 2008: 01 02 03... ...',
    ],
    'byte data, xa, upper case': [
        '    .BYT 1, 2, 3, $FF                                                 // 2008: 01 02 03... ...',
    ],
    'byte data, 64tass': [
        '    .byte 1, 2, 3, $ff                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, 64tass, upper case': [
        '    .BYTE 1, 2, 3, $FF                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, ca65': [
        '    .byte 1, 2, 3, $ff                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, ca65, upper case': [
        '    .BYTE 1, 2, 3, $FF                                                ; 2008: 01 02 03... ...',
    ],
    'byte data, z88dk-8080': [
        '    db 1, 2, 3, $ff                                                   ; 2008: 01 02 03... ...',
    ],
    'byte data, z88dk-8080, upper case': [
        '    DB 1, 2, 3, $FF                                                   ; 2008: 01 02 03... ...',
    ],
    'byte data, sjasmplus': [
        '    db 1, 2, 3, $ff                                                   ; 2008: 01 02 03... ...',
    ],
    'byte data, sjasmplus, upper case': [
        '    DB 1, 2, 3, $FF                                                   ; 2008: 01 02 03... ...',
    ],
    'byte data, two per line, acme': [
        '    !byte 1,   2                                                      ; 2008: 01 02       ..',
        '    !byte 3, $ff                                                      ; 200a: 03 ff       ..',
    ],
    'byte data, two per line, beebasm': [
        '    equb 1,   2                                                       ; 2008: 01 02       ..',
        '    equb 3, &ff                                                       ; 200a: 03 ff       ..',
    ],
    'byte data, two per line, xa': [
        '    .byt 1,   2                                                       // 2008: 01 02       ..',
        '    .byt 3, $ff                                                       // 200a: 03 ff       ..',
    ],
    'byte data, two per line, 64tass': [
        '    .byte 1,   2                                                      ; 2008: 01 02       ..',
        '    .byte 3, $ff                                                      ; 200a: 03 ff       ..',
    ],
    'byte data, two per line, ca65': [
        '    .byte 1,   2                                                      ; 2008: 01 02       ..',
        '    .byte 3, $ff                                                      ; 200a: 03 ff       ..',
    ],
    'word data, acme': [
        '    !word $1234, $5678                                                ; 200c: 34 12 78... 4.x',
    ],
    'word data, beebasm': [
        '    equw &1234, &5678                                                 ; 200c: 34 12 78... 4.x',
    ],
    'word data, xa': [
        '    .word $1234, $5678                                                // 200c: 34 12 78... 4.x',
    ],
    'word data, 64tass': [
        '    .word $1234, $5678                                                ; 200c: 34 12 78... 4.x',
    ],
    'word data, ca65': [
        '    .word $1234, $5678                                                ; 200c: 34 12 78... 4.x',
    ],
    'word data, z88dk-8080': [
        '    dw $1234, $5678                                                   ; 200c: 34 12 78... 4.x',
    ],
    'word data, sjasmplus': [
        '    dw $1234, $5678                                                   ; 200c: 34 12 78... 4.x',
    ],
    'string, acme': [
        '    !text "Hi!", $0d                                                  ; 2010: 48 69 21... Hi!',
    ],
    'string, acme, upper case': [
        '    !TEXT "Hi!", $0D                                                  ; 2010: 48 69 21... Hi!',
    ],
    'string, beebasm': [
        '    equs "Hi!", &0d                                                   ; 2010: 48 69 21... Hi!',
    ],
    'string, beebasm, upper case': [
        '    EQUS "Hi!", &0D                                                   ; 2010: 48 69 21... Hi!',
    ],
    'string, xa': [
        '    .asc "Hi!", $0d                                                   // 2010: 48 69 21... Hi!',
    ],
    'string, xa, upper case': [
        '    .ASC "Hi!", $0D                                                   // 2010: 48 69 21... Hi!',
    ],
    'string, 64tass': [
        '    .text "Hi!", $0d                                                  ; 2010: 48 69 21... Hi!',
    ],
    'string, 64tass, upper case': [
        '    .TEXT "Hi!", $0D                                                  ; 2010: 48 69 21... Hi!',
    ],
    'string, ca65': [
        '    .byte "Hi!", $0d                                                  ; 2010: 48 69 21... Hi!',
    ],
    'string, ca65, upper case': [
        '    .BYTE "Hi!", $0D                                                  ; 2010: 48 69 21... Hi!',
    ],
    'ASCII string with a quote, acme': [
        '    !text "H", \'"\', "i", \'"\'                                          ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, acme, upper case': [
        '    !TEXT "H", \'"\', "i", \'"\'                                          ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, beebasm': [
        '    equs "H", \'"\', "i", \'"\'                                           ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, beebasm, upper case': [
        '    EQUS "H", \'"\', "i", \'"\'                                           ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, xa': [
        '    .asc "H", 34, "i", 34, ""                                         // 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, xa, upper case': [
        '    .ASC "H", 34, "i", 34, ""                                         // 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, 64tass': [
        '    .text "H""i"""                                                    ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, 64tass, upper case': [
        '    .TEXT "H""i"""                                                    ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, ca65': [
        '    .byte "H", \'"\', "i", \'"\'                                          ; 2010: 48 22 69... H"i',
    ],
    'ASCII string with a quote, ca65, upper case': [
        '    .BYTE "H", \'"\', "i", \'"\'                                          ; 2010: 48 22 69... H"i',
    ],
    'operand with a low byte in an expression, acme': [
        '    lda #(<table) + 1                                                 ; 2000: a9 41       .A',
    ],
    'operand with a low byte in an expression, beebasm': [
        '    lda #(<table) + 1                                                 ; 2000: a9 41       .A',
    ],
    'operand with a low byte in an expression, xa': [
        '    lda #(table & $ff) + 1                                            // 2000: a9 41       .A',
    ],
    'operand with a low byte in an expression, 64tass': [
        '    lda #(<table) + 1                                                 ; 2000: a9 41       .A',
    ],
    'operand with a low byte in an expression, ca65': [
        '    lda #(<table) + 1                                                 ; 2000: a9 41       .A',
    ],
    'PETSCII string, acme': [
        '    !pet "Hello", \'"\', $0d                                            ; 2010: c8 45 4c... Hel',
    ],
    'PETSCII string, acme, upper case': [
        '    !PET "Hello", \'"\', $0D                                            ; 2010: C8 45 4C... Hel',
    ],
    'PETSCII string, beebasm': [
        '    equb &c8, &45, &4c, &4c, &4f, &22 ; petscii "Hello", &22          ; 2010: c8 45 4c... Hel',
        '    equb &0d ; petscii &0d                                            ; 2016: 0d          .',
    ],
    'PETSCII string, beebasm, upper case': [
        '    EQUB &C8, &45, &4C, &4C, &4F, &22 ; petscii "Hello", &22          ; 2010: C8 45 4C... Hel',
        '    EQUB &0D ; petscii &0D                                            ; 2016: 0D          .',
    ],
    'PETSCII string, xa': [
        '    .byt $c8, $45, $4c, $4c, $4f, $22 // petscii "Hello", $22         // 2010: c8 45 4c... Hel',
        '    .byt $0d // petscii $0d                                           // 2016: 0d          .',
    ],
    'PETSCII string, xa, upper case': [
        '    .BYT $C8, $45, $4C, $4C, $4F, $22 // petscii "Hello", $22         // 2010: C8 45 4C... Hel',
        '    .BYT $0D // petscii $0D                                           // 2016: 0D          .',
    ],
    'PETSCII string, 64tass': [
        '    .text "Hello""", $0d                                              ; 2010: c8 45 4c... Hel',
    ],
    'PETSCII string, 64tass, upper case': [
        '    .TEXT "Hello""", $0D                                              ; 2010: C8 45 4C... Hel',
    ],
    'PETSCII string, ca65': [
        '    .byte "Hello", \'"\', $0d                                           ; 2010: c8 45 4c... Hel',
    ],
    'PETSCII string, ca65, upper case': [
        '    .BYTE "Hello", \'"\', $0D                                           ; 2010: C8 45 4C... Hel',
    ],
    'screen code string, acme': [
        '    !scr "@ab["                                                       ; 2010: 00 01 02... @ab',
    ],
    'screen code string, acme, upper case': [
        '    !SCR "@ab["                                                       ; 2010: 00 01 02... @ab',
    ],
    'screen code string, beebasm': [
        '    equb 0, 1, 2, &1b ; screen "@ab["                                 ; 2010: 00 01 02... @ab',
    ],
    'screen code string, beebasm, upper case': [
        '    EQUB 0, 1, 2, &1B ; screen "@ab["                                 ; 2010: 00 01 02... @ab',
    ],
    'screen code string, xa': [
        '    .byt 0, 1, 2, $1b // screen "@ab["                                // 2010: 00 01 02... @ab',
    ],
    'screen code string, xa, upper case': [
        '    .BYT 0, 1, 2, $1B // screen "@ab["                                // 2010: 00 01 02... @ab',
    ],
    'screen code string, 64tass': [
        '    .enc "screencodes"',
        '    .text "@ab["                                                      ; 2010: 00 01 02... @ab',
        '    .enc "none"',
    ],
    'screen code string, 64tass, upper case': [
        '    .ENC "screencodes"',
        '    .TEXT "@ab["                                                      ; 2010: 00 01 02... @ab',
        '    .ENC "none"',
    ],
    'screen code string, ca65': [
        '    .byte 0, 1, 2, $1b ; screen "@ab["                                ; 2010: 00 01 02... @ab',
    ],
    'screen code string, ca65, upper case': [
        '    .BYTE 0, 1, 2, $1B ; screen "@ab["                                ; 2010: 00 01 02... @ab',
    ],
    "ASCII string with PETSCII the session's encoding, acme": [
        '    !text "Hi!", $0d                                                  ; 2010: 48 69 21... Hi!',
    ],
    "ASCII string with PETSCII the session's encoding, beebasm": [
        '    equs "Hi!", &0d                                                   ; 2010: 48 69 21... Hi!',
    ],
    "ASCII string with PETSCII the session's encoding, xa": [
        '    .asc "Hi!", $0d                                                   // 2010: 48 69 21... Hi!',
    ],
    "ASCII string with PETSCII the session's encoding, 64tass": [
        '    .enc "none"',
        '    .text "Hi!", $0d                                                  ; 2010: 48 69 21... Hi!',
        '    .enc "petscii"',
    ],
    "ASCII string with PETSCII the session's encoding, ca65": [
        '    .byte $48, $69, $21, $0d ; ascii "Hi!", $0d                       ; 2010: 48 69 21... Hi!',
    ],
    'PETSCII string over two lines, beebasm': [
        '    equb &c8, &45, &4c, &4c, &4f, &22 ; petscii "Hello", &22          ; 2010: c8 45 4c... Hel',
        '    equb &0d, &c8, &45, &4c, &4c, &4f ; petscii &0d, "Hello"          ; 2016: 0d c8 45... .He',
        '    equb &22, &0d ; petscii &22, &0d                                  ; 201c: 22 0d       ".',
    ],
    "byte data with PETSCII the session's encoding, acme": [
        '    !byte $48, $69, $21, $0d                                          ; 2010: 48 69 21... h.!',
    ],
    "byte data with PETSCII the session's encoding, beebasm": [
        '    equb &48, &69, &21, &0d                                           ; 2010: 48 69 21... h.!',
    ],
    "byte data with PETSCII the session's encoding, xa": [
        '    .byt $48, $69, $21, $0d                                           // 2010: 48 69 21... h.!',
    ],
    "byte data with PETSCII the session's encoding, 64tass": [
        '    .byte $48, $69, $21, $0d                                          ; 2010: 48 69 21... h.!',
    ],
    "byte data with PETSCII the session's encoding, ca65": [
        '    .byte $48, $69, $21, $0d                                          ; 2010: 48 69 21... h.!',
    ],
    'blank, acme': [
        '',
    ],
    'blank, beebasm': [
        '',
    ],
    'blank, xa': [
        '',
    ],
    'blank, 64tass': [
        '',
    ],
    'blank, ca65': [
        '',
    ],
    'one line comment, acme': [
        '; Memory locations',
    ],
    'one line comment, beebasm': [
        '; Memory locations',
    ],
    'one line comment, xa': [
        '// Memory locations',
    ],
    'one line comment, 64tass': [
        '; Memory locations',
    ],
    'one line comment, ca65': [
        '; Memory locations',
    ],
    'one line comment, z88dk-8080': [
        '; Memory locations',
    ],
    'one line comment, sjasmplus': [
        '; Memory locations',
    ],
    'empty one line comment, acme': [
        ';',
    ],
    'empty one line comment, beebasm': [
        ';',
    ],
    'empty one line comment, xa': [
        '//',
    ],
    'empty one line comment, 64tass': [
        ';',
    ],
    'empty one line comment, ca65': [
        ';',
    ],
    'word wrapped comment, acme': [
        '    ; This is a long comment which is word wrapped, since it is much too long to fit on\n    ; one line of the output.',
    ],
    'word wrapped comment, beebasm': [
        '    ; This is a long comment which is word wrapped, since it is much too long to fit on\n    ; one line of the output.',
    ],
    'word wrapped comment, xa': [
        '    // This is a long comment which is word wrapped, since it is much too long to fit\n    // on one line of the output.',
    ],
    'word wrapped comment, 64tass': [
        '    ; This is a long comment which is word wrapped, since it is much too long to fit on\n    ; one line of the output.',
    ],
    'word wrapped comment, ca65': [
        '    ; This is a long comment which is word wrapped, since it is much too long to fit on\n    ; one line of the output.',
    ],
    'constant definition, acme': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, acme, upper case': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, beebasm': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, beebasm, upper case': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, xa': [
        'lives       = 3         // Starting number of lives',
    ],
    'constant definition, xa, upper case': [
        'lives       = 3         // Starting number of lives',
    ],
    'constant definition, 64tass': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, 64tass, upper case': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, ca65': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, ca65, upper case': [
        'lives       = 3         ; Starting number of lives',
    ],
    'constant definition, z88dk-8080': [
        'lives       equ 3       ; Starting number of lives',
    ],
    'constant definition, z88dk-8080, upper case': [
        'lives       EQU 3       ; Starting number of lives',
    ],
    'constant definition, sjasmplus': [
        'lives       equ 3       ; Starting number of lives',
    ],
    'constant definition, sjasmplus, upper case': [
        'lives       EQU 3       ; Starting number of lives',
    ],
    'code start, acme': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, acme, upper case': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, beebasm': [
        '',
        '    org &2000',
        '',
    ],
    'code start, beebasm, upper case': [
        '',
        '    ORG &2000',
        '',
    ],
    'code start, xa': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, xa, upper case': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, 64tass': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, 64tass, upper case': [
        '',
        '    * = $2000',
        '',
    ],
    'code start, ca65': [
        '',
        '    .org $2000',
        '',
    ],
    'code start, ca65, upper case': [
        '',
        '    .ORG $2000',
        '',
    ],
    'code start, z88dk-8080': [
        '',
        '    org $2000',
        '',
    ],
    'code start, z88dk-8080, upper case': [
        '',
        '    ORG $2000',
        '',
    ],
    'code start, sjasmplus': [
        '',
        '    org $2000',
        '',
    ],
    'code start, sjasmplus, upper case': [
        '',
        '    ORG $2000',
        '',
    ],
    'code start, after other code, xa': [
        'end_of_part_1',
        '    * = $3000',
        '.dsb (*-end_of_part_1), 0',
        '    * = $3000',
        '',
    ],
    'code start, after other code, xa, upper case': [
        'end_of_part_1',
        '    * = $3000',
        '.DSB (*-end_of_part_1), 0',
        '    * = $3000',
        '',
    ],
    'code start, after other code, ca65': [
        '',
        '    .res $3000 - *',
        '    .org $3000',
        '',
    ],
    'code start, after other code, ca65, upper case': [
        '',
        '    .RES $3000 - *',
        '    .ORG $3000',
        '',
    ],
    'code start, after other code, sjasmplus': [
        '',
        '    ds $3000 - $',
        '    org $3000',
        '',
    ],
    'code start, after other code, sjasmplus, upper case': [
        '',
        '    DS $3000 - $',
        '    ORG $3000',
        '',
    ],
    'include binary file, acme': [
        '    !binary "data.bin"',
    ],
    'include binary file, acme, upper case': [
        '    !BINARY "data.bin"',
    ],
    'include binary file, beebasm': [
        '    incbin "data.bin"',
    ],
    'include binary file, beebasm, upper case': [
        '    INCBIN "data.bin"',
    ],
    'include binary file, xa': [
        '    .bin 0,0,"data.bin"',
    ],
    'include binary file, xa, upper case': [
        '    .BIN 0,0,"data.bin"',
    ],
    'include binary file, 64tass': [
        '    .binary "data.bin"',
    ],
    'include binary file, 64tass, upper case': [
        '    .BINARY "data.bin"',
    ],
    'include binary file, ca65': [
        '    .incbin "data.bin"',
    ],
    'include binary file, ca65, upper case': [
        '    .INCBIN "data.bin"',
    ],
    'include binary file, z88dk': [
        '    binary "data.bin"',
    ],
    'include binary file, z88dk, upper case': [
        '    BINARY "data.bin"',
    ],
    'include binary file, sjasmplus': [
        '    incbin "data.bin"',
    ],
    'include binary file, sjasmplus, upper case': [
        '    INCBIN "data.bin"',
    ],
    '6510 undocumented opcode, immediate, acme': [
        '    anc #$81                                                          ; 2000: 0b 81       ..',
    ],
    '6510 undocumented opcode, immediate, acme, upper case': [
        '    ANC #$81                                                          ; 2000: 0B 81       ..',
    ],
    '6510 undocumented opcode, immediate, beebasm': [
        '    equb &0b, &81 ; anc #&81 (undocumented)                           ; 2000: 0b 81       ..',
    ],
    '6510 undocumented opcode, immediate, beebasm, upper case': [
        '    EQUB &0B, &81 ; ANC #&81 (undocumented)                           ; 2000: 0B 81       ..',
    ],
    '6510 undocumented opcode, immediate, xa': [
        '    .byt $0b, $81 // anc #$81 (undocumented)                          // 2000: 0b 81       ..',
    ],
    '6510 undocumented opcode, immediate, xa, upper case': [
        '    .BYT $0B, $81 // ANC #$81 (undocumented)                          // 2000: 0B 81       ..',
    ],
    '6510 undocumented opcode, immediate, 64tass': [
        '    anc #$81                                                          ; 2000: 0b 81       ..',
    ],
    '6510 undocumented opcode, immediate, 64tass, upper case': [
        '    ANC #$81                                                          ; 2000: 0B 81       ..',
    ],
    '6510 undocumented opcode, immediate, ca65': [
        '    anc #$81                                                          ; 2000: 0b 81       ..',
    ],
    '6510 undocumented opcode, immediate, ca65, upper case': [
        '    ANC #$81                                                          ; 2000: 0B 81       ..',
    ],
    '6510 ALR, which acme calls ASR, acme': [
        '    asr #$0f                                                          ; 2000: 4b 0f       K.',
    ],
    '6510 ALR, which acme calls ASR, beebasm': [
        '    equb &4b, &0f ; alr #&0f (undocumented)                           ; 2000: 4b 0f       K.',
    ],
    '6510 ALR, which acme calls ASR, xa': [
        '    .byt $4b, $0f // alr #$0f (undocumented)                          // 2000: 4b 0f       K.',
    ],
    '6510 ALR, which acme calls ASR, 64tass': [
        '    alr #$0f                                                          ; 2000: 4b 0f       K.',
    ],
    '6510 ALR, which acme calls ASR, ca65': [
        '    alr #$0f                                                          ; 2000: 4b 0f       K.',
    ],
    '6510 LXA, which ca65 calls LAX, acme': [
        '    lxa #$12                                                          ; 2000: ab 12       ..',
    ],
    '6510 LXA, which ca65 calls LAX, 64tass': [
        '    lxa #$12                                                          ; 2000: ab 12       ..',
    ],
    '6510 LXA, which ca65 calls LAX, ca65': [
        '    lax #$12                                                          ; 2000: ab 12       ..',
    ],
    '6510 SBX, which ca65 calls AXS, acme': [
        '    sbx #$12                                                          ; 2000: cb 12       ..',
    ],
    '6510 SBX, which ca65 calls AXS, 64tass': [
        '    sbx #$12                                                          ; 2000: cb 12       ..',
    ],
    '6510 SBX, which ca65 calls AXS, ca65': [
        '    axs #$12                                                          ; 2000: cb 12       ..',
    ],
    "6510 undocumented opcode acme doesn't use, acme": [
        '    !byte $2b, $81 ; anc #$81 (undocumented)                          ; 2000: 2b 81       +.',
    ],
    "6510 undocumented opcode acme doesn't use, beebasm": [
        '    equb &2b, &81 ; anc #&81 (undocumented)                           ; 2000: 2b 81       +.',
    ],
    "6510 undocumented opcode acme doesn't use, xa": [
        '    .byt $2b, $81 // anc #$81 (undocumented)                          // 2000: 2b 81       +.',
    ],
    "6510 undocumented opcode acme doesn't use, 64tass": [
        '    .byte $2b, $81 ; anc #$81 (undocumented)                          ; 2000: 2b 81       +.',
    ],
    "6510 undocumented opcode acme doesn't use, ca65": [
        '    .byte $2b, $81 ; anc #$81 (undocumented)                          ; 2000: 2b 81       +.',
    ],
    '6510 undocumented opcode, implied, acme': [
        '    !byte $1a ; nop (undocumented)                                    ; 2000: 1a          .',
    ],
    '6510 undocumented opcode, implied, beebasm': [
        '    equb &1a ; nop (undocumented)                                     ; 2000: 1a          .',
    ],
    '6510 undocumented opcode, implied, xa': [
        '    .byt $1a // nop (undocumented)                                    // 2000: 1a          .',
    ],
    '6510 undocumented opcode, implied, 64tass': [
        '    .byte $1a ; nop (undocumented)                                    ; 2000: 1a          .',
    ],
    '6510 undocumented opcode, implied, ca65': [
        '    .byte $1a ; nop (undocumented)                                    ; 2000: 1a          .',
    ],
    '6510 JAM, with cycles, acme': [
        '    jam                                                               ; 2000: 02          .   halts',
    ],
    '6510 JAM, with cycles, beebasm': [
        '    equb &02 ; jam (undocumented)                                     ; 2000: 02          .   halts',
    ],
    '6510 JAM, with cycles, xa': [
        '    .byt $02 // jam (undocumented)                                    // 2000: 02          .   halts',
    ],
    '6510 JAM, with cycles, 64tass': [
        '    jam                                                               ; 2000: 02          .   halts',
    ],
    '6510 JAM, with cycles, ca65': [
        '    jam                                                               ; 2000: 02          .   halts',
    ],
    '6510 undocumented opcode as data, zero page operand, beebasm': [
        '    equb &b3, ptr ; lax (ptr),y (undocumented)                        ; 2000: a9 41       .A',
    ],
    '6510 undocumented opcode as data, zero page operand, beebasm, upper case': [
        '    EQUB &B3, ptr ; LAX (ptr),Y (undocumented)                        ; 2000: A9 41       .A',
    ],
    '6510 undocumented opcode as data, zero page operand, xa': [
        '    .byt $b3, ptr // lax (ptr),y (undocumented)                       // 2000: a9 41       .A',
    ],
    '6510 undocumented opcode as data, zero page operand, xa, upper case': [
        '    .BYT $B3, ptr // LAX (ptr),Y (undocumented)                       // 2000: A9 41       .A',
    ],
    'start, for the 6510, acme': [
        '!cpu 6510',
        '',
    ],
    'start, for the 6510, acme, upper case': [
        '!CPU 6510',
        '',
    ],
    'start, for the 6510, 64tass': [
        '.cpu "6502i"',
        '',
    ],
    'start, for the 6510, 64tass, upper case': [
        '.CPU "6502i"',
        '',
    ],
    'start, for the 6510, ca65': [
        '; Assemble with ca65 and its linker (from cc65), to a plain binary:',
        ';     cl65 -t none -C ca65.cfg -o program.bin this_file.asm',
        "; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:",
        ';     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }',
        ';     SEGMENTS { CODE: load = MAIN, type = rw; }',
        "; ('-t none': cl65's default target is the C64, whose character map would change",
        '; the strings.)',
        '',
        '    .setcpu "6502X"',
        '',
    ],
    'start, for the 6510, ca65, upper case': [
        '; Assemble with ca65 and its linker (from cc65), to a plain binary:',
        ';     cl65 -t none -C ca65.cfg -o program.bin this_file.asm',
        "; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:",
        ';     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }',
        ';     SEGMENTS { CODE: load = MAIN, type = rw; }',
        "; ('-t none': cl65's default target is the C64, whose character map would change",
        '; the strings.)',
        '',
        '    .SETCPU "6502X"',
        '',
    ],
    'start, for the 65C02, acme': [
        '!cpu 65c02',
        '',
    ],
    'start, for the 65C02, acme, upper case': [
        '!CPU 65C02',
        '',
    ],
    'start, for the 65C02, 64tass': [
        '.cpu "65c02"',
        '',
    ],
    'start, for the 65C02, 64tass, upper case': [
        '.CPU "65c02"',
        '',
    ],
    'start, for the 65C02, ca65': [
        '; Assemble with ca65 and its linker (from cc65), to a plain binary:',
        ';     cl65 -t none -C ca65.cfg -o program.bin this_file.asm',
        "; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:",
        ';     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }',
        ';     SEGMENTS { CODE: load = MAIN, type = rw; }',
        "; ('-t none': cl65's default target is the C64, whose character map would change",
        '; the strings.)',
        '',
        '    .setcpu "65C02"',
        '',
    ],
    'start, for the 65C02, ca65, upper case': [
        '; Assemble with ca65 and its linker (from cc65), to a plain binary:',
        ';     cl65 -t none -C ca65.cfg -o program.bin this_file.asm',
        "; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:",
        ';     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }',
        ';     SEGMENTS { CODE: load = MAIN, type = rw; }',
        "; ('-t none': cl65's default target is the C64, whose character map would change",
        '; the strings.)',
        '',
        '    .SETCPU "65C02"',
        '',
    ],
    'Z80 operand with low and high bytes, z88dk': [
        '    ld a, (table & $ff) + (table >> 8)                                ; 2000: a9 41       .A',
    ],
    'Z80 operand with low and high bytes, z88dk, upper case': [
        '    LD A, (table & $FF) + (table >> 8)                                ; 2000: A9 41       .A',
    ],
    'Z80 operand with low and high bytes, sjasmplus': [
        '    ld a, (low table) + (high table)                                  ; 2000: a9 41       .A',
    ],
    'Z80 operand with low and high bytes, sjasmplus, upper case': [
        '    LD A, (LOW table) + (HIGH table)                                  ; 2000: A9 41       .A',
    ],
    'Z80 character literals, z88dk': [
        '    ld a, \'\\\'\' + \'\\\\\' + \'"\'                                           ; 2000: a9 41       .A',
    ],
    'Z80 character literals, sjasmplus': [
        '    ld a, "\'" + \'\\\' + \'"\'                                             ; 2000: a9 41       .A',
    ],
    'move start and end, z88dk': [
        '    phase $8000',
        '    dephase',
        '',
    ],
    'move start and end, z88dk, upper case': [
        '    PHASE $8000',
        '    DEPHASE',
        '',
    ],
    'move start and end, sjasmplus': [
        '    disp $8000',
        '    ent',
        '',
    ],
    'move start and end, sjasmplus, upper case': [
        '    DISP $8000',
        '    ENT',
        '',
    ],
    'start, sjasmplus': [
        '; Assemble with sjasmplus, to a plain binary:',
        ';     sjasmplus --nologo --raw=program.bin this_file.asm',
        '',
    ],
    'start, sjasmplus, upper case': [
        '; Assemble with sjasmplus, to a plain binary:',
        ';     sjasmplus --nologo --raw=program.bin this_file.asm',
        '',
    ],
    'end, with assertions, z88dk': [
        '; ASSERT ((flags - err_nr) == -$36)',
        '; ASSERT ((table) == $1234)',
    ],
    'end, with assertions, z88dk, upper case': [
        '; ASSERT ((flags - err_nr) == -$36)',
        '; ASSERT ((table) == $1234)',
    ],
    'end, with assertions, sjasmplus': [
        '    assert (flags - err_nr) == -$36',
        '    assert (table) == $1234',
    ],
    'end, with assertions, sjasmplus, upper case': [
        '    ASSERT (flags - err_nr) == -$36',
        '    ASSERT (table) == $1234',
    ],
    'end, saving to a file, acme': [
        '!to "Out.bin", plain',
    ],
    'end, saving to a file, acme, upper case': [
        '!TO "Out.bin", PLAIN',
    ],
    'end, saving to a file, beebasm': [
        '',
        'save "Out.bin", pydis_start, pydis_end',
    ],
    'end, saving to a file, beebasm, upper case': [
        '',
        'SAVE "Out.bin", pydis_start, pydis_end',
    ],
}

def render(make_line, assembler, upper_case=False):
    """The text of the line made by make_line(), for the given assembler."""
    import session
    s = session.new_session(assembler=assembler, lower_case=not upper_case)
    s.memory.binary[0x2000:0x2000 + len(MEMORY)] = MEMORY
    line = make_line()
    return [str(text) for text in line.render()]

def main():
    sys.path.insert(0, str(PY8DIS_DIR))
    sys.argv = sys.argv[:1] + [a for a in sys.argv[1:] if a == "--print"]
    printing = "--print" in sys.argv
    import commands
    commands.use_command_line(False)

    failures = 0
    count = 0
    for name, assemblers, make_line in make_tests():
        for assembler in assemblers:
            for upper_case in ((False, True) if name.endswith(" *") else (False,)):
                key = "%s, %s%s" % (name.rstrip(" *"), assembler, ", upper case" if upper_case else "")
                got = render(make_line, assembler, upper_case)
                count += 1
                if printing:
                    print("    %r: [" % key)
                    for text in got:
                        print("        %r," % text)
                    print("    ],")
                elif EXPECTED.get(key) != got:
                    failures += 1
                    print("FAILED: %s" % key)
                    print("    expected: %r" % (EXPECTED.get(key),))
                    print("    got:      %r" % (got,))
    if not printing:
        print("render tests: %d passed, %d failed" % (count - failures, failures))
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
