#!/usr/bin/env python3
"""
Run the py8dis example tests.

For each test and assembler:
  1. Run the control file in python/ to produce build/<test>_<assembler>.asm
     and build/<test>_<assembler>.json (with --json, see docs/json-format.md)
  2. With -c, check that the asm is identical to known_good/<test>_<assembler>.asm.
     Check the JSON: that it matches the schema (docs/py8dis-json.schema.json,
     if the jsonschema package is installed), that its items cover the
     loaded data exactly, that each expression's tree gives its value (where
     it can be worked out), that each item's text matches the asm, that the
     labels agree with the items, and that the comments, constants,
     subroutines and memory regions agree with the asm and the labels
  3. If the assembler is installed, assemble the asm and check the binary is
     identical to orig/<test>.orig. If the assembler isn't installed this step
     is skipped, but the check in step 2 still happens (so e.g. CI can run
     without any assemblers installed).
     For the tests in EXTRAS_KNOWN_GOOD, also check the JSON is identical to
     known_good/<test>_<assembler>.json.
  4. With -m, copy the asm to known_good (only once the binary has been
     checked), and the JSON for the tests in EXTRAS_KNOWN_GOOD

The error tests (ERROR_TESTS below) are control files in python/errors/ that
py8dis should stop with an error for, e.g. an expr() with the wrong value. Each
passes if py8dis fails with exactly the expected message as the last line of
its error output. They're run with beebasm, whose hex format the messages use.
The warning tests (WARNING_TESTS) are control files in python/warnings/ that
should run successfully and give the expected warning.

With -c, when all the tests are run, session_tests.py (several disassemblies in
one process) and render_tests.py (rendering output lines for each assembler)
are run as well: see those files. They're started first and reported first.

Tests run in parallel. Examples:

  ./run_tests.py -c                     # run and check all tests
  ./run_tests.py -c move move2          # just these tests
  ./run_tests.py -c -a acme             # just the acme versions of the tests
  ./run_tests.py -m regression_tests    # make known good files
"""

import argparse
import concurrent.futures
import filecmp
import json
import re
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Each test is (name, assemblers, description). The control file is
# python/<name>.py and the original binary is orig/<name>.orig.
TESTS = [
    # 8080 code
    ("example8080",              ["z88dk-8080"],               "hello world example for the 8080 instruction set"),
    ("test8080",                 ["z88dk-8080"],               "testing the whole 8080 instruction set"),
    ("regression_tests_8080",    ["z88dk-8080"],               "regression tests for z88dk expression operators"),
    ("undocumented_8080",        ["z88dk-8080"],               "the 8080's undocumented opcodes, traced as what they run as and output as data"),
    ("move_8080",                ["z88dk-8080"],               "move() and include_binary_file() with z88dk-z80asm (PHASE and BINARY)"),

    # Z80 code
    ("test_z80",                 ["z88dk"],                    "every documented Z80 instruction"),
    ("undocumented_z80",         ["z88dk"],                    "the Z80's undocumented opcodes: those z88dk-z80asm accepts as instructions, the others as data"),
    ("redundant_z80",            ["z88dk"],                    "redundant Z80 instructions (whose results aren't used)"),
    ("state_z80",                ["z88dk"],                    "what's known about the Z80's registers and flags after each instruction"),
    ("spectrum48",               ["z88dk"],                    "the ZX Spectrum 48K ROM, with spectrum.spectrum48() and spectrum.rom()"),
    ("spectrum_test",            ["z88dk"],                    "a ZX Spectrum program, with spectrum.spectrum48(): ROM calls, system variables, RST $10, $28 and $08, the border and keyboard"),
    ("trace_z80",                ["z88dk"],                    "tracing Z80 code: RST with a hook, JP (IX), relative jumps round the top and bottom of memory, moves, expressions"),
    ("bbcbasic",                 ["z88dk"],                    "BBC BASIC (Z80) for CP/M, with labels from its map file, hooks for inline data and tables of routines"),
    ("zexdoc",                   ["z88dk"],                    "ZEXDOC, the Z80 instruction exerciser for CP/M: mostly tables, with self-modifying code"),
    ("opense",                   ["z88dk"],                    "OpenSE BASIC, a replacement ZX Spectrum ROM, with spectrum.spectrum48() and the spectrum module's tables"),

    # 6502 code: tests
    ("include_binary_file",      ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for including a binary file"),
    ("char_literals",            ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for all character literals"),
    ("align_test",               ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for formatting"),
    ("cycles",                   ["acme", "beebasm", "xa", "64tass", "ca65"],    "cycle counts for branches near page boundaries"),
    ("redundant_test",           ["acme", "beebasm", "xa", "64tass", "ca65"],    "redundant instructions (whose results aren't used), with io_range() and the BIT trick"),
    ("branch_state",             ["acme", "beebasm", "xa", "64tass", "ca65"],    "registers known after a BNE that isn't taken (after DEY, CMP #n etc.)"),
    ("string_stuff1",            ["acme", "beebasm", "64tass"],"xa and ca65 omitted since they can't do string constants e.g. 'page = \"1900\"'"),
    ("string_stuff2",            ["beebasm"],                  "testing the beebasm specific expression 'STR$~(page)'"),
    ("string_stuff3",            ["acme", "beebasm", "xa", "64tass", "ca65"],    "testing py8dis string commands"),
    ("moving1",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for the move() command"),
    ("moving2",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for the move() command"),
    ("moving3",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "tests for the move() command"),
    ("helloworld",               ["acme", "beebasm", "xa", "64tass", "ca65"],    "the basic hello world test"),
    ("local_labels",             ["acme", "beebasm", "xa", "64tass", "ca65"],    "labels defined as local to one move region"),
    ("move",                     ["acme", "beebasm", "xa", "64tass", "ca65"],    "a move() test"),
    ("move2",                    ["acme", "beebasm", "xa", "64tass", "ca65"],    "another move() test"),
    ("move2_legacy_label_maker", ["acme", "beebasm", "xa", "64tass", "ca65"],    "move2 with a legacy label maker hook choosing a move"),
    ("move_from_top_of_memory",  ["acme", "beebasm", "xa", "64tass", "ca65"],    "a move() whose source ends at &10000"),
    ("move_to_top_of_memory",    ["acme", "beebasm", "xa", "64tass", "ca65"],    "a move() whose destination ends at &10000"),
    ("top_of_memory",            ["acme", "beebasm", "xa", "64tass", "ca65"],    "code at the top of memory, and a branch that wraps round to zero page"),
    ("top_of_memory_string",     ["acme", "beebasm", "xa", "64tass", "ca65"],    "a string found by autostring() that runs up to &ffff"),
    ("bottom_of_memory",         ["acme", "beebasm", "xa", "64tass", "ca65"],    "a branch that wraps round below &0000"),
    ("split",                    ["acme", "beebasm", "xa", "64tass", "ca65"],    "loads *two* binary files to disassemble"),
    ("subroutine_test",          ["acme", "beebasm", "xa", "64tass", "ca65"],    "demonstrates the use of the subroutine() command"),
    ("regression_tests",         ["acme", "beebasm", "xa", "64tass", "ca65"],    "regression tests for fixed bugs"),
    ("expressions",              ["acme", "beebasm", "xa", "64tass", "ca65"],    "how expressions are bracketed for each assembler"),
    ("acorn_os_calls",           ["acme", "beebasm", "xa", "64tass", "ca65"],    "test all the os calls for acorn machines"),
    ("acorn_vectors",            ["acme", "beebasm", "xa", "64tass", "ca65"],    "the ways of setting an Acorn OS vector that acorn.py recognises"),
    ("acorn_vdu",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "VDU sequences written with OSWRCH, decoded by acorn.py"),
    ("acorn_lower_case_os_calls", ["acme", "beebasm", "xa", "64tass", "ca65"],   "Acorn OS calls named in lower case, with config.set_upper_case_os_calls(False)"),
    ("effect_patterns",          ["acme", "beebasm", "xa", "64tass", "ca65"],    "effect patterns: snippets matching the values code stores, and the registers at a call"),
    ("prg_test",                 ["acme", "beebasm", "xa", "64tass", "ca65"],    "a Commodore PRG file loaded with load_prg(), which reassembles to the whole file"),
    ("p00_test",                 ["acme", "beebasm", "xa", "64tass", "ca65"],    "a PC64 P00 file loaded with load_prg()"),
    ("load_offset",              ["acme", "beebasm", "xa", "64tass", "ca65"],    "loading parts of a file with load(..., offset=..., length=...)"),
    ("undocumented_6502",        ["acme", "beebasm", "xa", "64tass", "ca65"],    "every undocumented 6502 opcode, with load(..., \"6510\")"),
    ("petscii_test",             ["acme", "beebasm", "xa", "64tass", "ca65"],    "PETSCII and screen code strings, with config.set_text_encoding()"),
    ("c64_test",                 ["acme", "beebasm", "xa", "64tass", "ca65"],    "a C64 program (a PRG file with a BASIC SYS line), with commodore.c64()"),
    ("c64_names_test",           ["acme", "beebasm", "xa", "64tass", "ca65"],    "c64_test with commodore.c64(names=\"commodore\"), and a name clash"),
    ("cartridge_test",           ["acme", "beebasm", "xa", "64tass", "ca65"],    "a C64 cartridge, with commodore.is_cartridge()"),
    ("vic20_test",               ["acme", "beebasm", "xa", "64tass", "ca65"],    "a VIC-20 program, with commodore.vic20()"),
    ("vic20_8k_test",            ["acme", "beebasm", "xa", "64tass", "ca65"],    "vic20_test for a VIC-20 with 8K or more RAM"),
    ("vic20_cartridge_test",     ["acme", "beebasm", "xa", "64tass", "ca65"],    "a VIC-20 cartridge, with commodore.is_cartridge()"),
    ("c128_test",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "a C128 program, with commodore.c128(): the MMU, the VDC, PRIMM and JSRFAR"),
    ("plus4_test",               ["acme", "beebasm", "xa", "64tass", "ca65"],    "a Plus/4 program, with commodore.plus4(): the TED, the ACIA and PRIMM"),
    ("pet4_test",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "a PET program for BASIC 4 with 80 columns (commodore.pet())"),
    ("pet2_test",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "the PET program for BASIC 2"),
    ("pet1_test",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "the PET program for BASIC 1, with Commodore's names"),
    ("drive1541_test",           ["acme", "beebasm", "xa", "64tass", "ca65"],    "code for the 1541 disk drive (commodore.drive1541()): its job queue, buffers, VIAs and DOS ROM"),
    ("drive1541_names_test",     ["acme", "beebasm", "xa", "64tass", "ca65"],    "drive1541_test for the 1541-II's DOS ROM, with Commodore's names"),
    ("fastload_test",            ["acme", "beebasm", "xa", "64tass", "ca65"], "a C64 program with code for the 1541 in it (commodore.drive1541_code())"),
    ("c128_banks_test",          ["acme", "beebasm", "xa", "64tass", "ca65"],    "a C128 program that changes the MMU's configuration"),

    # 6502 code: real programs
    ("os12",                     ["acme", "beebasm", "xa", "64tass", "ca65"],    "MOS 1.20"),
    ("basic4",                   ["acme", "beebasm", "xa", "64tass", "ca65"],    "BASIC 4"),
    ("dfs226",                   ["acme", "beebasm", "xa", "64tass", "ca65"],    "DFS 2.26"),
    ("dfs226b",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "DFS with an artificially added move() just for testing"),
    ("anfs418",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "Network filing system 4.18"),
    ("lisp406",                  ["acme", "beebasm", "64tass", "ca65"],"Lisp 4.06 (xa is excluded since it can't cope with: 'ldx #(>(LISPEN-LISVAL-1))+1'; for 64tass its '_AND' is 'AND_', since 64tass takes a label starting with '_' to be local)"),
    ("chuckie",                  ["acme", "beebasm", "xa", "64tass", "ca65"],    "Chuckie Egg"),
    ("planb",                    ["acme", "beebasm", "xa", "64tass", "ca65"],    "Plan B with the old style label_maker function"),
    ("planb_new_label_maker",    ["acme", "beebasm", "xa", "64tass", "ca65"],    "Plan B with a new style label_maker function"),
    ("starship",                 ["acme", "beebasm", "xa", "64tass", "ca65"],    "Starship Command"),
    ("open_roms_kernal",         ["acme", "beebasm", "xa", "64tass", "ca65"],    "the Kernal ROM of MEGA65's Open ROMs, a free replacement for the C64's"),
    ("open_roms_basic",          ["acme", "beebasm", "xa", "64tass", "ca65"],    "the BASIC ROM of MEGA65's Open ROMs"),
    ("quikman2k8",               ["acme", "beebasm", "xa", "64tass", "ca65"],    "Quikman 2K8, a VIC-20 game"),
    ("memory128",                ["acme", "beebasm", "xa", "64tass", "ca65"],    "memory128, a C128 game for the 80 column screen"),
]

# The tests whose other outputs are also compared with known_good: the JSON
# (see docs/json-format.md), the symbol file and the cross-reference listing,
# as known_good/<test>_<assembler>.json, .symbols and .xref. (The JSON of every
# test is checked, see check_json(), and every beebasm symbol file is checked
# against beebasm's own, but these show any change to the outputs
# themselves.)
EXTRAS_KNOWN_GOOD = ["helloworld", "regression_tests", "move2", "local_labels", "subroutine_test", "test8080", "undocumented_8080", "prg_test", "undocumented_6502", "petscii_test", "c64_test", "vic20_test", "c128_test", "test_z80", "undocumented_z80", "trace_z80", "state_z80", "spectrum_test", "branch_state", "redundant_z80"]

# The symbol file format made for each assembler's tests, so that each format
# is tested (see py8dis/symbols.py)
SYMBOLS_FORMATS = {"beebasm": "beebasm", "acme": "vice", "xa": "mame", "64tass": "vice", "ca65": "vice", "z88dk-8080": "plain", "z88dk": "plain"}

# Each error test is (name, expected error message). The control file is
# python/errors/<name>.py (which describes the test), and py8dis must stop with
# this message (the last line of its error output). Run with beebasm.
ERROR_TESTS = [
    ("expr_wrong_byte",         "expr() at &200a: 'length + 2' is &0f, but the byte there is &0e"),
    ("expr_wrong_word",         "expr() at &2003: 'message + 1' is &200f, but the word there is &200e"),
    ("expr_dict_missing",       "expr(&200a, ...): the dictionary has no entry for the value &0e found at this address"),
    ("address_out_of_range",    "label(&10001): the address must be between &0000 and &10000"),
    ("local_label_bad_name",    "local_label(&200e, '1message'): this isn't a valid label name (a letter or underscore followed by letters, digits or underscores)"),
    ("no_data_loaded",          "comment(&3000): no data is loaded at this address (data is loaded from 'orig/helloworld.orig' at &2000-&201b)"),
    ("already_classified",      "byte(&2010, ...): &2010 has already been classified (e.g. by an earlier byte(), word() or string command)"),
    ("move_same_addresses",     "move(&2000, &2000, 16): the source and destination are the same"),
    ("memory_region_bad_end",   "memory_region(&80, &70, ...): the end must be after the start"),
    ("load_different_cpu",      "All calls to load() must use the same CPU (already using 'Cpu6502', now asked for '65c02')."),
    ("use_command_line_late",   "use_command_line(False) must be called before any other command (the command line has already been read)"),
    ("label_maker_hook_twice",  "set_label_maker_hook() can only be called once"),
    ("load_missing_file",       "load(&2000, 'orig/no_such_file.orig'): can't read the file (No such file or directory)"),
    ("load_wrong_md5",          "load(&2000, 'orig/helloworld.orig'): the file's md5sum is ba85fca1feae301af81806d3102b0851, not 0123456789abcdef0123456789abcdef as expected"),
    ("load_past_top",           "load(&fff0, 'orig/helloworld.orig'): the file (28 bytes) runs past the top of memory"),
    ("go_without_load",         "go(): nothing has been loaded to disassemble (use load() first)"),
    ("load_offset_past_end",    "load(&2000, 'orig/helloworld.orig'): the offset (28) is past the end of the file (28 bytes)"),
    ("load_length_past_end",    "load(&2000, 'orig/helloworld.orig'): the offset and length (20 + 10) run past the end of the file (28 bytes)"),
    ("load_bad_offset",         "load(&2000, 'orig/helloworld.orig'): the offset must be a whole number, 0 or more, not -1"),
    ("load_prg_too_short",      "load_prg('build/too_short.prg'): the file (2 bytes) is too short to be a PRG file (two bytes of load address, then the data)"),
    ("upper_case_os_calls_too_late", "config.set_upper_case_os_calls(): call it before acorn.bbc(), commodore.c64() etc., which name the OS calls"),
    ("c128_bank_without_c128",  "commodore.c128_bank(): call commodore.c128() first"),
    ("c128_bank_bad_bank",      "commodore.c128_bank(): the bank must be 0-15, not 16"),
    ("pet_80_columns_basic_2",  "commodore.pet(): only BASIC 4 PETs have 80 columns"),
    ("tass64_local_label_name", "64tass takes a label starting with '_' to be local to the label before it, so '_count' can't be used: rename it"),
    ("ca65_register_label",     "ca65 doesn't accept 'x' as a label, since it's a register's name: rename it"),
    ("ca65_mnemonic_label",     "ca65 doesn't accept 'lax' as a label, since it's an instruction's mnemonic: rename it"),
    ("drive1541_bad_rom",       "commodore.drive1541(): rom must be one of '1541', '1541-ii', not '1571'"),
    ("drive1541_kernal_rom",    "commodore.kernal_rom(): the 1541 has no Kernal (use dos_rom())"),
    ("drive1541_code_in_drive", "commodore.drive1541_code(): this is already the 1541's disassembly (drive1541())"),
    ("effect_register_without_anchor", "register_snippet(): a register line ('x = ...') needs an instruction line, to say where it applies"),
    ("effect_bad_value",        "register_snippet(): a value is a number, a name or '?': '[$70] = 1+2'"),
    ("effect_unbound_variable", "register_snippet(): the variable 'vec' isn't given its addresses (e.g. '[vec = $70 | $72]')"),
]

# Each warning test is (name, expected warning). The control file is
# python/warnings/<name>.py, which must run successfully (with beebasm) and
# give this warning (as one line of its error output).
WARNING_TESTS = [
    ("load_prg_file",           "warning: load(&07ff, 'build/load_prg_file.prg'): this looks like a Commodore PRG file, whose first two bytes are the address to load it at, not data; load_prg('build/load_prg_file.prg') loads it at that address without them"),
    ("move_splits_data",        "warning: move boundary at binary address &3002 splits a classification"),
]

# The program each assembler needs
ASSEMBLER_PROGRAMS = {
    "acme":       "acme",
    "beebasm":    "beebasm",
    "xa":         "xa",
    "64tass":     "64tass",
    "ca65":       "cl65",
    "z88dk-8080": "z88dk-z80asm",
    "z88dk":      "z88dk-z80asm",
}

# Test scripts run as well by -c, when all the tests are run
OTHER_TEST_SCRIPTS = ["session_tests.py", "render_tests.py"]

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"
JSON_SCHEMA  = EXAMPLES_DIR.parent / "docs" / "py8dis-json.schema.json"


class Paths:
    def __init__(self, name, assembler):
        self.control_file  = Path("python")     / f"{name}.py"
        self.original      = Path("orig")       / f"{name}.orig"
        self.asm           = Path("build")      / f"{name}_{assembler}.asm"
        self.json          = Path("build")      / f"{name}_{assembler}.json"
        self.binary        = Path("build")      / f"{name}_{assembler}.dat"
        self.known_good    = Path("known_good") / f"{name}_{assembler}.asm"
        self.known_good_json = Path("known_good") / f"{name}_{assembler}.json"
        self.py8dis_symbols = Path("build")      / f"{name}_{assembler}.symbols"
        self.xref          = Path("build")      / f"{name}_{assembler}.xref"
        self.known_good_symbols = Path("known_good") / f"{name}_{assembler}.symbols"
        self.known_good_xref    = Path("known_good") / f"{name}_{assembler}.xref"
        self.beebasm_symbols = Path("build")    / f"{name}_{assembler}_beebasm_symbols.txt"
        self.assembler_symbols = Path("build")  / f"{name}_{assembler}_assembler_symbols.txt"
        self.report        = Path("build")      / f"{name}_{assembler}_report.txt"
        self.symbols       = Path("build")      / f"{name}_{assembler}_symbols.txt"


class Result:
    """The outcome of one test with one assembler."""
    def __init__(self, name, assembler):
        self.name = name
        self.assembler = assembler
        self.failure = None         # A message if the test failed
        self.notes = []             # e.g. "not assembled: acme not found"
        self.stderr = ""            # Anything py8dis printed to stderr (e.g. warnings)


def first_difference(file1, file2):
    """Describe the first line that differs between two text files."""
    lines1 = file1.read_text(errors="replace").splitlines()
    lines2 = file2.read_text(errors="replace").splitlines()
    for i, (a, b) in enumerate(zip(lines1, lines2)):
        if a != b:
            return f"first difference at line {i+1}:\n      got:      {a.rstrip()}\n      expected: {b.rstrip()}"
    return f"files differ in length ({len(lines1)} lines vs {len(lines2)} lines expected)"


def assemble_command(assembler, p, make_extras):
    """Return the command line to assemble p.asm into p.binary."""
    if assembler == "acme":
        cmd = ["acme", "-o", str(p.binary)]
        if make_extras:
            cmd += ["--report", str(p.report), "-l", str(p.symbols)]
        return cmd + [str(p.asm)]
    if assembler == "beebasm":
        # (-d writes beebasm's own symbol dump, to check py8dis's against)
        return ["beebasm", "-v", "-o", str(p.binary), "-i", str(p.asm), "-d", "-labels", str(p.beebasm_symbols)]
    if assembler == "xa":
        cmd = ["xa", str(p.asm), "-o", str(p.binary)]
        if make_extras:
            cmd += ["-l", str(p.symbols), "-P", str(p.report)]
        return cmd
    if assembler == "64tass":
        # (-b: a plain binary, without a load address. --vice-labels -l
        # writes 64tass's own symbols, to check py8dis's against.)
        # (-I .: 64tass looks for a .binary file relative to the asm file's
        # folder, then the include folders)
        cmd = ["64tass", "-q", "-b", "-I", ".", "-o", str(p.binary), "--vice-labels", "-l", str(p.assembler_symbols)]
        if make_extras:
            cmd += ["-L", str(p.report)]
        return cmd + [str(p.asm)]
    if assembler == "ca65":
        # (ca65 then its linker, ld65, with the configuration for a plain
        # binary; '-t none', since cl65's default target is the C64, whose
        # character map would change the strings. -g -Ln writes ld65's own
        # symbols, to check py8dis's against.)
        cmd = ["cl65", "-t", "none", "-g", "-C", "ca65.cfg", "-o", str(p.binary), "-Ln", str(p.assembler_symbols)]
        if make_extras:
            cmd += ["-l", str(p.report)]
        return cmd + [str(p.asm)]
    if assembler in ("z88dk-8080", "z88dk"):
        # (The tests of 8080 code use the name "z88dk-8080", and of Z80
        # code "z88dk": it's the same assembler, told which CPU it is)
        cmd = ["z88dk-z80asm", "-m8080" if assembler == "z88dk-8080" else "-mz80", "-b"]
        if make_extras:
            cmd += ["-l", "-s"]
        return cmd + ["-o" + str(p.binary), str(p.asm)]
    raise ValueError(f"unknown assembler '{assembler}'")


_json_validator = None

def json_validator():
    """A validator for the JSON schema, or None if the jsonschema package
    isn't installed."""
    global _json_validator
    if _json_validator is None:
        try:
            import jsonschema
        except ImportError:
            _json_validator = False
        else:
            # The schema is draft 2020-12, but uses nothing that draft 7
            # doesn't have, so jsonschema before 4.0 (which has no
            # Draft202012Validator) checks it the same way with draft 7
            validator = getattr(jsonschema, "Draft202012Validator", None) or jsonschema.Draft7Validator
            _json_validator = validator(json.loads(JSON_SCHEMA.read_text()))
    return _json_validator or None

def json_sample(doc):
    """The JSON with its long lists ('items' and 'labels') cut down to a
    sample, for checking against the schema: up to 10 entries with each set
    of keys (and type), so that every kind of entry is checked. (Checking
    the whole of e.g. os12's JSON with jsonschema takes about a second, which
    for all the tests would double the time they take.)"""
    def sample(entries):
        result = []
        counts = {}
        for entry in entries:
            key = (entry.get("type"), tuple(sorted(entry)))
            counts[key] = counts.get(key, 0) + 1
            if counts[key] <= 2:
                result.append(entry)
        return result
    return dict(doc, items=sample(doc["items"]), labels=sample(doc["labels"])) if isinstance(doc, dict) and "items" in doc and "labels" in doc else doc

# The operators in expression trees, as py8dis evaluates them (see
# expression.py)
JSON_BINARY_OPERATORS = {
    "+":   lambda a, b: a + b,
    "-":   lambda a, b: a - b,
    "*":   lambda a, b: a * b,
    "DIV": lambda a, b: a // b if b != 0 and a >= 0 and b > 0 else None,
    "MOD": lambda a, b: a % b if b != 0 and a >= 0 and b > 0 else None,
    "AND": lambda a, b: a & b,
    "OR":  lambda a, b: a | b,
    "EOR": lambda a, b: a ^ b,
    "<<":  lambda a, b: a << b if a >= 0 and 0 <= b < 32 else None,
    ">>":  lambda a, b: a >> b if a >= 0 and 0 <= b < 32 else None,
}
JSON_UNARY_OPERATORS = {
    "<":   lambda a: a & 0xff if a >= 0 else None,
    ">":   lambda a: (a >> 8) & 0xff if a >= 0 else None,
    "NOT": lambda a: ~a,
    "-":   lambda a: -a,
}

def evaluate_json_tree(tree):
    """The value of an expression tree in the JSON, or None if it can't be
    worked out (e.g. it uses a name, or a string written by the user)."""
    if "num" in tree:
        return tree["num"]
    if "label" in tree:
        return tree["label"]
    if "left" in tree:
        a, b = evaluate_json_tree(tree["left"]), evaluate_json_tree(tree["right"])
        op = JSON_BINARY_OPERATORS.get(tree["op"])
        return None if a is None or b is None or op is None else op(a, b)
    if "arg" in tree:
        a = evaluate_json_tree(tree["arg"])
        op = JSON_UNARY_OPERATORS.get(tree["op"])
        return None if a is None or op is None else op(a)
    return None

# The hex dump in the asm, e.g. '   ; 2000: a2 00   ..': the binary address
HEX_DUMP = re.compile(r"\s*(?:;|//) ([0-9a-f]{4}): [0-9a-f]{2}")

def asm_lines_by_address(asm_path):
    """The asm's code lines (without the hex dump and anything after it,
    whitespace collapsed) for each binary address, from the hex dump, or None
    if there's no hex dump. (Comments, e.g. for overlapping instructions, are
    left out.)"""
    result = {}
    for line in asm_path.read_text().splitlines():
        m = HEX_DUMP.search(line)
        if m and not line.lstrip().startswith((";", "//")):
            result.setdefault(int(m.group(1), 16), []).append(" ".join(line[:m.start()].split()))
    return result or None

SIMPLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

def check_json_labels(path, doc):
    """Check the JSON's labels agree with its items, returning a message
    describing the first problem, or None."""
    labels = {}
    for label in doc["labels"]:
        addr = label["runtime_addr"]
        if labels and addr <= max(labels):
            return f"{path}: the label at {addr:#06x} is out of order, or listed twice"
        labels[addr] = label

    def names_at(addr):
        """All the names the asm can use for an address."""
        label = labels.get(addr, {})
        return ({n["name"] for n in label.get("names", [])} |
                {n.get("output_name", n["name"]) for n in label.get("local_names", [])} |
                {e["text"] for e in label.get("expressions", [])})

    def label_leaves(tree):
        if "label" in tree:
            yield tree
        for key in ("arg", "left", "right"):
            if key in tree:
                yield from label_leaves(tree[key])

    item_at = {}            # (binary address of each byte) -> item
    inline_at = {}          # runtime address -> the names defined inline there
    for item in doc["items"]:
        where = f"{path}: the item at {item['binary_addr']:#06x}"
        for i in range(item["length"]):
            item_at[item["binary_addr"] + i] = item
        inline_at.setdefault(item["runtime_addr"], set()).update(item.get("labels", []))

        # Its labels are names of its address, defined inline
        label = labels.get(item["runtime_addr"], {})
        inline = {n["name"] for n in label.get("names", []) if n["definition"] == "inline"}
        for name in item.get("labels", []):
            if name not in inline:
                return f"{where}: its label {name!r} isn't an inline name of the label at {item['runtime_addr']:#06x}"

        # The labels used by its expressions have those names
        exprs = [item["operand"]["expr"]] if "operand" in item else []
        exprs += [e for e in item.get("exprs", []) if e is not None]
        for e in exprs:
            for leaf in label_leaves(e["tree"]):
                # (A name can also be an expression relative to another
                # label, e.g. brkv+1)
                if SIMPLE_NAME.fullmatch(leaf["name"]) and leaf["name"] not in names_at(leaf["label"]):
                    return f"{where}: its expression {e['text']!r} uses the name {leaf['name']!r} for {leaf['label']:#06x}, which isn't one of that label's names"

    # The starts and ends of ranges, with their labels
    previous = None
    for end in doc["range_boundaries"]:
        key = (end["binary_addr"], end.get("move_id", 0))
        where = f"{path}: the range boundary at {end['binary_addr']:#06x}"
        if previous is not None and key <= previous:
            return f"{where} is out of order, or listed twice"
        previous = key
        label = labels.get(end["runtime_addr"], {})
        inline = {n["name"] for n in label.get("names", []) if n["definition"] == "inline"}
        for name in end.get("labels", []):
            if name not in inline:
                return f"{where}: its label {name!r} isn't an inline name of the label at {end['runtime_addr']:#06x}"
        inline_at.setdefault(end["runtime_addr"], set()).update(end.get("labels", []))

    for addr, label in labels.items():
        where = f"{path}: the label at {addr:#06x}"
        # Each inline name is defined by an item there, or at the start or
        # end of a range there. (Not necessarily in the name's own move: a
        # name for a move that's never output at its address is defined in
        # another one.)
        for n in label.get("names", []):
            if n["definition"] == "inline" and n["name"] not in inline_at.get(addr, set()):
                return f"{where}: its inline name {n['name']!r} isn't defined by any item or range boundary there"
        # Each reference is from an item, at the runtime address it runs at
        for ref in label.get("references", []):
            item = item_at.get(ref["binary_addr"])
            if item is None:
                return f"{where}: its reference from {ref['binary_addr']:#06x} isn't in any item"
            if ref["runtime_addr"] != item["runtime_addr"] + (ref["binary_addr"] - item["binary_addr"]):
                return f"{where}: its reference from {ref['binary_addr']:#06x} gives the runtime address {ref['runtime_addr']:#06x}, but that item runs at {item['runtime_addr']:#06x}"
    return None

def check_json_annotations(path, doc, asm):
    """Check the JSON's comments, constants, subroutines and memory regions
    agree with the asm and its labels, returning a message describing the
    first problem, or None."""
    def collapse(text):
        # (Comment prefixes are removed, and whitespace collapsed, so that
        # word wrapped comments can be found)
        return " ".join(text.replace("//", " ").replace(";", " ").split())
    asm_text = collapse(asm)

    for item in doc["items"] + doc["range_boundaries"]:
        for c in item.get("comments", []):
            text = c["text"]
            if c.get("kind") == "overlapping":
                text = text.split(None, 1)[0]       # ("overlapping:", since the instruction is laid out)
            if collapse(text) not in asm_text:
                return f"{path}: the comment {c['text']!r} at {item['binary_addr']:#06x} isn't in the asm"

    asm_lines = asm.splitlines()
    for c in doc["constants"]:
        if not any(c["name"] in line and c["text"] in line for line in asm_lines):
            return f"{path}: the constant {c['name']!r} = {c['text']!r} isn't defined in the asm"

    labels = {label["runtime_addr"]: label for label in doc["labels"]}
    for s in doc["subroutines"]:
        if "name" in s:
            names = {n["name"] for n in labels.get(s["runtime_addr"], {}).get("names", [])}
            if s["name"] not in names:
                return f"{path}: the subroutine {s['name']!r} at {s['runtime_addr']:#06x} isn't a name of the label there"

    regions = doc["memory_regions"]
    if regions != sorted(regions, key=lambda r: (r["start"], r["start"] - r["end"])):
        return f"{path}: the memory regions are out of order"
    # (A local name can have a heading of its own: commodore.py's 'Other
    # banks', for the C128's names in other banks, and '1541 drive', for the
    # names in drive code)
    own_headings = {"Other banks", "1541 drive"}
    region_names = {r["name"] for r in regions} | {"Other"} | own_headings
    # The headings in the asm, e.g. '; Zero page (&0000-&00ff)' or '; Other'
    # (z88dk writes an address below &100 with two digits, e.g. '; ROM ($00-$3fff)')
    prefix = re.escape(asm_comment_prefix(asm))
    asm_headings = set(re.findall("^" + prefix + r" (.*?) \([&$][0-9a-fA-F]{2,4}-[&$][0-9a-fA-F]{2,4}\)$", asm, re.M))
    for heading in {"Other"} | own_headings:
        if re.search("^" + prefix + " " + re.escape(heading) + "$", asm, re.M):
            asm_headings.add(heading)
    for label in doc["labels"]:
        for n in label.get("names", []) + label.get("local_names", []):
            if "memory_region" in n and n["memory_region"] not in region_names:
                return f"{path}: the label at {label['runtime_addr']:#06x} is under the heading {n['memory_region']!r}, which isn't a memory region"
            if "memory_region" in n and n["memory_region"] not in asm_headings:
                return f"{path}: the label at {label['runtime_addr']:#06x} is under the heading {n['memory_region']!r}, which isn't in the asm"
    return None

def asm_comment_prefix(asm):
    """The comment prefix the asm uses (';' or '//')."""
    return "//" if re.search(r"^//", asm, re.M) else ";"

def check_json(path, asm_path=None):
    """Check the JSON output (see docs/json-format.md), returning a message
    describing the first problem, or None."""
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        return f"{path} isn't valid JSON: {e}"

    validator = json_validator()
    if validator is not None:
        error = next(iter(sorted(validator.iter_errors(json_sample(doc)), key=lambda e: list(e.path))), None)
        if error is not None:
            return f"{path} doesn't match the schema at {'/'.join(str(x) for x in error.path) or 'the top'}: {error.message}"

    # The items must cover the loaded data exactly, each with the bytes loaded
    # there (later loads replacing earlier ones, as py8dis does)
    loaded = {}
    for load in doc["loads"]:
        offset = load.get("offset", 0)
        data = Path(load["filename"]).read_bytes()[offset:offset + load["end"] - load["start"]]
        if load["start"] + len(data) != load["end"]:
            return f"{path}: the load of {load['filename']} at {load['start']:#06x} should end at {load['start'] + len(data):#06x}, not {load['end']:#06x}"
        for i, b in enumerate(data):
            loaded[load["start"] + i] = b
    covered = set()
    for item in doc["items"]:
        start = item["binary_addr"]
        if len(item["bytes"]) != item["length"]:
            return f"{path}: the item at {start:#06x} has {len(item['bytes'])} bytes, but its length is {item['length']}"
        for i, b in enumerate(item["bytes"]):
            addr = start + i
            if addr in covered:
                return f"{path}: the item at {start:#06x} overlaps another at {addr:#06x}"
            if addr not in loaded:
                return f"{path}: the item at {start:#06x} includes {addr:#06x}, where nothing is loaded"
            if loaded[addr] != b:
                return f"{path}: the item at {start:#06x} has {b:#04x} at {addr:#06x}, but {loaded[addr]:#04x} is loaded there"
            covered.add(addr)
    missing = sorted(set(loaded) - covered)
    if missing:
        return f"{path}: no item covers the loaded data at {missing[0]:#06x}" + (f" (and {len(missing) - 1} more bytes)" if len(missing) > 1 else "")

    # Each expression's tree gives its value (where it can be worked out)
    for item in doc["items"]:
        where = f"{path}: the item at {item['binary_addr']:#06x}"
        checks = []
        if "operand" in item:
            checks.append((item["operand"]["expr"], item["operand"]["value"]))
        for e, value in zip(item.get("exprs", []), item.get("values", [])):
            if e is not None:
                checks.append((e, value))
        for e, value in checks:
            v = evaluate_json_tree(e["tree"])
            if v is not None and v != value:
                return f"{where}: the expression {e['text']!r} has the value {v}, not {value}"
            if "operand" in item and e is item["operand"]["expr"] and e["text"] not in item["text"][0]:
                return f"{where}: the operand {e['text']!r} isn't in its text {item['text'][0]!r}"

    # The labels agree with the items
    problem = check_json_labels(path, doc)
    if problem:
        return problem

    # The comments, constants, subroutines and memory regions agree with the
    # asm and the labels
    if asm_path is not None:
        problem = check_json_annotations(path, doc, asm_path.read_text())
        if problem:
            return problem

    # Each item's text matches the asm (where the asm has a hex dump, giving
    # the binary address of each line)
    if asm_path is not None:
        by_address = asm_lines_by_address(asm_path)
        if by_address is not None:
            for item in doc["items"]:
                if item["type"] == "include_binary":
                    continue            # (it has no hex dump)
                start = item["binary_addr"]
                asm = [line for addr in range(start, start + item["length"]) for line in by_address.get(addr, [])]
                text = [" ".join(t.split()) for t in item["text"]]
                if len(asm) != len(text) or not all(a.startswith(t) for a, t in zip(asm, text)):
                    return f"{path}: the item at {start:#06x} has the text {item['text']!r}, but the asm has {asm!r}"
    return None


def beebasm_symbols(text):
    """The symbols in beebasm's symbol dump format ('[{'name':8192L,...}]'),
    as a dictionary."""
    return {name: int(float(value)) for name, value in re.findall(r"'([^']*)':(-?[0-9.e+]+)L", text)}


def vice_symbols(text):
    """The symbols in a VICE label file ('al 00FFEE .name', or 64tass's 'al
    ffee .name'), as a dictionary."""
    return {name: int(value, 16) for value, name in re.findall(r"^al ([0-9A-Fa-f]+) \.(\S+)$", text, re.MULTILINE)}


def run_test(name, assembler, options, env):
    """Run one test with one assembler, returning a Result."""
    result = Result(name, assembler)
    p = Paths(name, assembler)

    # 1. Run py8dis
    proc = subprocess.run([sys.executable, str(p.control_file), "--" + assembler, "--json", str(p.json),
                           "--symbols", str(p.py8dis_symbols), "--symbols-format", SYMBOLS_FORMATS[assembler], "--xref", str(p.xref)],
                          capture_output=True, text=True, env=env)
    result.stderr = proc.stderr.strip()
    if proc.returncode != 0:
        result.failure = "py8dis failed"
        return result
    p.asm.write_text(proc.stdout)

    # 2. Check the asm against known good
    if options.check_disassembly:
        if not p.known_good.exists():
            result.failure = f"{p.known_good} not found"
            return result
        if not filecmp.cmp(p.asm, p.known_good, shallow=False):
            result.failure = f"{p.asm} differs from {p.known_good}, " + first_difference(p.asm, p.known_good)
            return result
        problem = check_json(p.json, p.asm)
        if problem:
            result.failure = problem
            return result
        if name in EXTRAS_KNOWN_GOOD:
            for got, expected in ((p.json, p.known_good_json), (p.py8dis_symbols, p.known_good_symbols), (p.xref, p.known_good_xref)):
                if not expected.exists():
                    result.failure = f"{expected} not found"
                    return result
                if not filecmp.cmp(got, expected, shallow=False):
                    result.failure = f"{got} differs from {expected}, " + first_difference(got, expected)
                    return result

    # 3. Assemble and check the binary, if the assembler is installed
    program = ASSEMBLER_PROGRAMS[assembler]
    if shutil.which(program) is None:
        result.notes.append(f"not assembled: {program} not found")
        if options.make_known_good:
            result.notes.append("known good not made, since the output wasn't assembled")
        return result

    proc = subprocess.run(assemble_command(assembler, p, options.make_extras), capture_output=True, text=True)
    if assembler == "beebasm" and options.make_extras:
        p.report.write_text(proc.stdout)
    if proc.returncode != 0:
        result.failure = f"{program} failed:\n" + (proc.stderr or proc.stdout).strip()
        return result
    if assembler == "ca65" and "Warning" in proc.stderr:
        # (e.g. "Didn't use zeropage addressing", for a zero page label used
        # before it's defined, which is assembled with the wrong bytes)
        result.failure = f"{program} gave a warning:\n" + proc.stderr.strip()
        return result
    if not filecmp.cmp(p.binary, p.original, shallow=False):
        result.failure = f"assembled binary {p.binary} differs from {p.original}"
        return result

    # beebasm's own symbols (its labels, defined as '.name') must all be in
    # py8dis's symbol file, with the same values
    if assembler == "beebasm":
        ours = beebasm_symbols(p.py8dis_symbols.read_text())
        for symbol, value in beebasm_symbols(p.beebasm_symbols.read_text()).items():
            if ours.get(symbol) != value:
                result.failure = f"beebasm gives {symbol} the value {value}, but py8dis's symbol file {p.py8dis_symbols} gives {ours.get(symbol)}"
                return result

    # 64tass's own symbols (its labels, not those defined with '=') must all
    # be in py8dis's symbol file, with the same values
    if assembler in ("64tass", "ca65"):
        ours = vice_symbols(p.py8dis_symbols.read_text())
        # (A name defined as 'name=...' in a control file's own text, e.g.
        # lisp406's 'DWARF=NERRC-1' from annotate(), is a label to 64tass if
        # its value is an address, but py8dis doesn't know about it)
        asm_text = p.asm.read_text()
        for symbol, value in vice_symbols(p.assembler_symbols.read_text()).items():
            if value in (0, 0x10000) and symbol not in ours:
                # (A label at &10000, after code at the top of memory, which
                # 64tass gives the value 0, and py8dis's VICE symbols leave
                # out)
                continue
            if symbol not in ours and re.search(r"^" + re.escape(symbol) + r"\s*=", asm_text, re.MULTILINE):
                continue
            if ours.get(symbol) != value:
                result.failure = f"{assembler} gives {symbol} the value {value}, but py8dis's symbol file {p.py8dis_symbols} gives {ours.get(symbol)}"
                return result

    # 4. Make known good
    if options.make_known_good:
        shutil.copy2(p.asm, p.known_good)
        if name in EXTRAS_KNOWN_GOOD:
            shutil.copy2(p.json, p.known_good_json)
            shutil.copy2(p.py8dis_symbols, p.known_good_symbols)
            shutil.copy2(p.xref, p.known_good_xref)
        result.notes.append("made known good")
    return result


def run_error_test(name, expected, env):
    """Run one error test, returning a Result."""
    result = Result(name, "error")
    proc = subprocess.run([sys.executable, str(Path("python") / "errors" / f"{name}.py"), "--beebasm"],
                          capture_output=True, text=True, env=env)
    lines = [line for line in proc.stderr.splitlines() if line.strip()]
    got = lines[-1] if lines else "<no error output>"
    if proc.returncode == 0:
        result.failure = f"py8dis didn't stop with an error\n      expected: {expected}"
    elif got != expected:
        result.failure = f"py8dis stopped with a different error:\n      got:      {got}\n      expected: {expected}"
    return result


def run_warning_test(name, expected, env):
    """Run one warning test, returning a Result."""
    result = Result(name, "warning")
    proc = subprocess.run([sys.executable, str(Path("python") / "warnings" / f"{name}.py"), "--beebasm"],
                          capture_output=True, text=True, env=env)
    lines = [line.strip() for line in proc.stderr.splitlines() if line.strip()]
    if proc.returncode != 0:
        result.failure = "py8dis stopped with an error:\n      " + (lines[-1] if lines else "<no error output>")
    elif expected not in lines:
        result.failure = f"py8dis didn't give the expected warning:\n      expected: {expected}\n      got:      " + ("\n                " .join(lines) or "<nothing>")
    return result


def main():
    parser = argparse.ArgumentParser(description="Run the py8dis example tests.")
    parser.add_argument("-c", "--check-disassembly", action="store_true", help="check the disassembly (asm) output against known_good")
    parser.add_argument("-m", "--make-known-good",   action="store_true", help="copy the disassembly output to known_good (once the binary is checked)")
    parser.add_argument("-x", "--make-extras",       action="store_true", help="create extra files for debugging (reports, symbol files etc)")
    parser.add_argument("-a", "--assemblers", nargs="+", choices=sorted(ASSEMBLER_PROGRAMS), help="only test with these assemblers")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1, help="number of tests to run at once (default: number of CPUs)")
    parser.add_argument("tests", nargs="*", help="names of the tests to run (default: all)")
    options = parser.parse_args()

    known_names = [name for name, _, _ in TESTS] + [name for name, _ in ERROR_TESTS] + [name for name, _ in WARNING_TESTS]
    unknown = [t for t in options.tests if t not in known_names]
    if unknown:
        parser.error("unknown test(s): {0}\nknown tests: {1}".format(", ".join(unknown), ", ".join(known_names)))

    os.chdir(EXAMPLES_DIR)
    Path("build").mkdir(exist_ok=True)
    Path("known_good").mkdir(exist_ok=True)

    # Use the py8dis in this repository
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(PY8DIS_DIR)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))

    jobs = [(name, assembler)
            for name, assemblers, _ in TESTS
            if not options.tests or name in options.tests
            for assembler in assemblers
            if not options.assemblers or assembler in options.assemblers]
    error_jobs = [(name, expected) for name, expected in ERROR_TESTS
                  if (not options.tests or name in options.tests) and not options.assemblers]
    warning_jobs = [(name, expected) for name, expected in WARNING_TESTS
                    if (not options.tests or name in options.tests) and not options.assemblers]

    start = time.time()
    failures = 0
    width = max([len(f"{n}_{a}") for n, a in jobs] + [len(f"{n}_error") for n, _ in error_jobs] + [len(f"{n}_warning") for n, _ in warning_jobs], default=0) + 2
    # The other test scripts, when checking all the tests. These start first
    # since the session tests take longest.
    other_scripts = OTHER_TEST_SCRIPTS if (options.check_disassembly and not options.tests and not options.assemblers) else []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, options.jobs)) as executor:
        other_futures = [executor.submit(subprocess.run, [sys.executable, script], capture_output=True, text=True, env=env)
                         for script in other_scripts]
        futures = [executor.submit(run_test, name, assembler, options, env) for name, assembler in jobs]
        futures += [executor.submit(run_error_test, name, expected, env) for name, expected in error_jobs]
        jobs += [(name, "error") for name, _ in error_jobs]
        futures += [executor.submit(run_warning_test, name, expected, env) for name, expected in warning_jobs]
        jobs += [(name, "warning") for name, _ in warning_jobs]
        # The other test scripts first, since they were started first
        for script, other_future in zip(other_scripts, other_futures):
            jobs.append((script, None))
            proc = other_future.result()
            label = (Path(script).stem + ":").ljust(width)
            if proc.returncode != 0:
                failures += 1
                print(f"{label}FAILED:")
                for line in (proc.stdout + proc.stderr).splitlines():
                    if not line.startswith("warning:") and not line.startswith("  passed:"):
                        print("    " + line)
            else:
                print(f"{label}passed")
            sys.stdout.flush()

        # Report in test order (each result waits for its own test to finish)
        for future in futures:
            r = future.result()
            label = f"{r.name}_{r.assembler}:".ljust(width)
            if r.failure:
                failures += 1
                print(f"{label}FAILED: {r.failure}")
            else:
                print(f"{label}passed" + (" (" + "; ".join(r.notes) + ")" if r.notes else ""))
            if r.stderr:
                for line in r.stderr.splitlines():
                    print("    " + line)
            sys.stdout.flush()

    print(f"\n{len(jobs) - failures} passed, {failures} failed ({time.time() - start:.1f}s)")
    if not options.check_disassembly:
        print("(Use -c to also check the disassembly against known_good.)")
    elif json_validator() is None:
        print("(The JSON wasn't checked against its schema, since the jsonschema package isn't installed: pip install jsonschema)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
