#!/usr/bin/env python3
"""
Run the py8dis tests

This is py8dis's main test script (docs/testing.md describes the tests for
users). Each test in TESTS disassembles a program from orig/ with its
control file from python/, once for each of the assemblers listed for it,
and checks the output. For each test and assembler:

  1. Run the control file in python/ (in a process of its own, using the
     py8dis in this repository) to produce build/<test>_<assembler>.asm,
     and as well the JSON (build/<test>_<assembler>.json, see
     docs/json-format.md), the symbol file (.symbols, in the format given
     in SYMBOLS_FORMATS) and the cross-reference listing (.xref).
  2. With -c, check that the asm is identical to known_good/<test>_<assembler>.asm.
     Check the JSON: that it matches the schema (docs/py8dis-json.schema.json,
     if the jsonschema package is installed), that its items cover the
     loaded data exactly, that each expression's tree gives its value (where
     it can be worked out), that each item's text matches the asm, that the
     labels agree with the items, and that the comments, constants,
     subroutines and memory regions agree with the asm and the labels.
     For the tests in EXTRAS_KNOWN_GOOD, also check that the JSON, the
     symbol file and the cross-reference listing are identical to the ones
     in known_good/.
  3. If the assembler is installed, assemble the asm and check the binary is
     identical to orig/<test>.orig. For beebasm, Baron, 64tass, ca65 and
     sjasmplus, also check that each label the assembler reports has the
     same value in py8dis's symbol file. If the assembler isn't installed
     this step is skipped, but the checks in step 2 still happen (so the
     output can still be checked on a machine without the assemblers).
  4. With -m, copy the asm to known_good (only once the binary has been
     checked, so not if the assembler isn't installed), and the JSON, the
     symbol file and the cross-reference listing for the tests in
     EXTRAS_KNOWN_GOOD.

The error tests (ERROR_TESTS below) are control files in python/errors/ that
py8dis should stop with an error for, e.g. an expr() with the wrong value. Each
passes if py8dis fails with exactly the expected message as the last line of
its error output. They're run with beebasm, whose hex format the messages use.
The warning tests (WARNING_TESTS) are control files in python/warnings/ that
should run successfully and give the expected warning. Neither kind is run
with -a.

With -c, when all the tests are run, session_tests.py (several disassemblies in
one process) and render_tests.py (rendering output lines for each assembler)
are run as well: see those files. They're started first and reported first.

The options (./run_tests.py --help lists them too):

  -c              check the output against known_good, as in step 2
  -m              copy the output to known_good, as in step 4, after a change
                  to py8dis that's meant to change it (the binary is still
                  checked)
  -x              make extra files in build/ for debugging: the assemblers'
                  reports, listings and symbol files
  -a ASSEMBLER... only test with these assemblers
  -j JOBS         how many tests to run at once (by default, the number of
                  CPUs)
  NAME...         only run these tests (names from TESTS, ERROR_TESTS or
                  WARNING_TESTS)

Tests run in parallel, each in a thread that starts py8dis and the
assembler as processes of their own. The results are printed in the order
of the lists below. The script exits with 1 if any test fails. Examples:

  ./run_tests.py -c                     # run and check all tests
  ./run_tests.py -c move move2          # just these tests
  ./run_tests.py -c -a acme             # just the acme versions of the tests
  ./run_tests.py -m regression_tests    # make known good files

To add a test of a disassembly, put the program in orig/<name>.orig (for a
small test program written for py8dis, put its source in
asm_to_create_test_binaries/ and add a line to the 'go' script there, which
builds the programs into orig/), write its control file python/<name>.py,
and add (name, assemblers, description) to TESTS. Then make its known good
files with './run_tests.py -m <name>' (with the assemblers installed, since
they're only made once the binary has been checked), and check them by hand.
Add its name to EXTRAS_KNOWN_GOOD as well to keep its JSON, symbol file and
cross-reference listing in known_good/ too.

To add an error test, write python/errors/<name>.py, with a docstring saying
what it tests, and add (name, the error message) to ERROR_TESTS. A warning
test is the same, with python/warnings/ and WARNING_TESTS.
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
# python/<name>.py and the original binary is orig/<name>.orig. The
# assemblers are names from ASSEMBLER_PROGRAMS below ("z88dk-8080" for 8080
# code and "z88dk" for Z80 code, both z88dk-z80asm), and the description is
# only for the reader. The tests are started, and reported, in this order.
TESTS = [
    # 8080 code
    ("example8080",              ["z88dk-8080"],               "hello world example for the 8080 instruction set"),
    ("indent_loops_8080",        ["z88dk-8080"],               "8080 code with its loops indented (config.set_indent_loops(True))"),
    ("test8080",                 ["z88dk-8080"],               "testing the whole 8080 instruction set"),
    ("regression_tests_8080",    ["z88dk-8080"],               "regression tests for z88dk expression operators"),
    ("undocumented_8080",        ["z88dk-8080"],               "the 8080's undocumented opcodes, traced as what they run as and output as data"),
    ("move_8080",                ["z88dk-8080"],               "move() and include_binary_file() with z88dk-z80asm (PHASE and BINARY)"),
    ("cpm_8080",                 ["z88dk-8080"],               "a CP/M program, with cpm.cpm(): BDOS calls, their function numbers, page zero, strings to print and FCBs"),

    # Z80 code
    ("test_z80",                 ["z88dk", "sjasmplus"],       "every documented Z80 instruction"),
    ("undocumented_z80",         ["z88dk", "sjasmplus"],       "the Z80's undocumented opcodes: those z88dk-z80asm accepts as instructions, the others as data"),
    ("redundant_z80",            ["z88dk", "sjasmplus"],       "redundant Z80 instructions (whose results aren't used)"),
    ("state_z80",                ["z88dk", "sjasmplus"],       "what's known about the Z80's registers and flags after each instruction"),
    ("banks_z80",                ["z88dk", "sjasmplus"],       "two banks of Z80 code that both run at $8000, loaded separately (z88dk-z80asm's DEFS for a gap)"),
    ("crash_fixes_z80",          ["z88dk", "sjasmplus"],       "Z80 code that used to crash py8dis: expr() on the address in an instruction with a prefix, and an instruction cut off by the end of the data"),
    ("spectrum48",               ["z88dk", "sjasmplus"],       "the ZX Spectrum 48K ROM, with spectrum.spectrum48() and spectrum.rom()"),
    ("spectrum_test",            ["z88dk", "sjasmplus"],       "a ZX Spectrum program, with spectrum.spectrum48(): ROM calls, system variables, RST $10, $28 and $08, the border and keyboard"),
    ("spectrum_no_rom",          ["z88dk", "sjasmplus"],       "a ZX Spectrum program, with spectrum.spectrum48(rom_labels=False): IY partly known, and no GEN-ENT-1 hook"),
    ("trace_z80",                ["z88dk", "sjasmplus"],       "tracing Z80 code: RST with a hook, JP (IX), relative jumps round the top and bottom of memory, moves, expressions"),
    ("bbcbasic",                 ["z88dk", "sjasmplus"],       "BBC BASIC (Z80) for CP/M, with cpm.cpm(), labels from its map file, hooks for inline data and tables of routines"),
    ("zexdoc",                   ["z88dk", "sjasmplus"],       "ZEXDOC, the Z80 instruction exerciser for CP/M, with cpm.cpm(): mostly tables, with self-modifying code"),
    ("opense",                   ["z88dk", "sjasmplus"],       "OpenSE BASIC, a replacement ZX Spectrum ROM, with spectrum.spectrum48() and the spectrum module's tables"),

    # 6502 code: tests
    ("include_binary_file",      ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for including a binary file"),
    ("char_literals",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for all character literals"),
    ("align_test",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for formatting"),
    ("cycles",                   ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "cycle counts for branches near page boundaries"),
    ("cycles_65c02",             ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "65C02 cycle counts: ADC and SBC in decimal mode, and absolute indexed BIT and shifts"),
    ("redundant_test",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "redundant instructions (whose results aren't used), with io_range() and the BIT trick"),
    ("branch_state",             ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "registers known after a BNE that isn't taken (after DEY, CMP #n etc.)"),
    ("string_stuff1",            ["acme", "beebasm", "baron", "64tass"],"xa and ca65 omitted since they can't do string constants e.g. 'page = \"1900\"'"),
    ("string_stuff2",            ["beebasm"],                  "testing the beebasm specific expression 'STR$~(page)'"),
    ("string_stuff3",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "testing py8dis string commands"),
    ("banks_test",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "two banks of code that both run at $8000 (moves to the same address), loaded separately, with a call that can't be told the bank of"),
    ("beebasm_moves",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a moved block that runs over the end of the program, for which beebasm's output moves only the bytes in the way"),
    ("moving1",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for the move() command"),
    ("moving2",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for the move() command"),
    ("moving3",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "tests for the move() command"),
    ("helloworld",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the basic hello world test"),
    ("local_labels",             ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "labels defined as local to one move region"),
    ("move",                     ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a move() test"),
    ("move2",                    ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "another move() test"),
    ("move2_legacy_label_maker", ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "move2 with a legacy label maker hook choosing a move"),
    ("move_from_top_of_memory",  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a move() whose source ends at &10000"),
    ("move_to_top_of_memory",    ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a move() whose destination ends at &10000"),
    ("top_of_memory",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "code at the top of memory, and a branch that wraps round to zero page"),
    ("top_of_memory_string",     ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a string found by autostring() that runs up to &ffff"),
    ("bottom_of_memory",         ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a branch that wraps round below &0000"),
    ("split",                    ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "loads *two* binary files to disassemble"),
    ("subroutine_test",          ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "demonstrates the use of the subroutine() command"),
    ("regression_tests",         ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "regression tests for fixed bugs"),
    ("crash_fixes",              ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "things that used to crash py8dis: splits inside an instruction and a word, substitute_constants() with RTS, a constant's align without a comment, expr_label() where moves overlap"),
    ("regex_snippets",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "regex snippets with one character operands, A, negative and binary values, a branch's offset in hex, and a name and an instruction on one line"),
    ("copy_loops",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "loops that copy or set memory, counting up or down, past zero or to a limit, with the comments from the built in snippets"),
    ("expressions",              ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "how expressions are bracketed for each assembler"),
    ("acorn_os_calls",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "test all the os calls for acorn machines"),
    ("acorn_vectors",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the ways of setting an Acorn OS vector that acorn.py recognises"),
    ("acorn_vdu",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "VDU sequences written with OSWRCH, decoded by acorn.py"),
    ("acorn_fixes",              ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "acorn.bbc()'s comments: VDU 31 with the column from X and the row from A after X changes, and a table of character row offsets as words"),
    ("acorn_lower_case_os_calls", ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Acorn OS calls named in lower case, with config.set_upper_case_os_calls(False)"),
    ("effect_patterns",          ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "effect patterns: snippets matching the values code stores, and the registers at a call"),
    ("prg_test",                 ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a Commodore PRG file loaded with load_prg(), which reassembles to the whole file"),
    ("p00_test",                 ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a PC64 P00 file loaded with load_prg()"),
    ("load_offset",              ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "loading parts of a file with load(..., offset=..., length=...)"),
    ("undocumented_6502",        ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "every undocumented 6502 opcode, with load(..., \"6510\")"),
    ("petscii_test",             ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "PETSCII and screen code strings, with config.set_text_encoding()"),
    ("c64_test",                 ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C64 program (a PRG file with a BASIC SYS line), with commodore.c64()"),
    ("c64_names_test",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "c64_test with commodore.c64(names=\"commodore\"), and a name clash"),
    ("c64_memory_test",          ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the C64's memory configuration (the 6510's port at $01), followed through the code, with c64_configuration()"),
    ("drive_code_names",         ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C64 program and its drive code both using $0300, each with its own machine's name for it (the C64 code's first)"),
    ("drive_code_fixes",         ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C64 program's drive code in the middle of buffer 0 (which isn't named), storing to $05 (not a job) and job 1"),
    ("cartridge_test",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C64 cartridge, with commodore.is_cartridge()"),
    ("vic20_test",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a VIC-20 program, with commodore.vic20()"),
    ("vic20_8k_test",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "vic20_test for a VIC-20 with 8K or more RAM"),
    ("vic20_cartridge_test",     ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a VIC-20 cartridge, with commodore.is_cartridge()"),
    ("c128_test",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C128 program, with commodore.c128(): the MMU, the VDC, PRIMM and JSRFAR"),
    ("c128_fixes",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C128 program with BASIC 7.0's keywords (two-byte ones too), and an MMU configuration with a function ROM at $d000"),
    ("plus4_test",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a Plus/4 program, with commodore.plus4(): the TED, the ACIA and PRIMM"),
    ("plus4_basic",              ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a Plus/4 program with BASIC 3.5's keywords"),
    ("pet4_test",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a PET program for BASIC 4 with 80 columns (commodore.pet())"),
    ("pet2_test",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the PET program for BASIC 2"),
    ("pet1_test",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the PET program for BASIC 1, with Commodore's names"),
    ("drive1541_test",           ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "code for the 1541 disk drive (commodore.drive1541()): its job queue, buffers, VIAs and DOS ROM"),
    ("drive1541_names_test",     ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "drive1541_test for the 1541-II's DOS ROM, with Commodore's names"),
    ("fastload_test",            ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C64 program with code for the 1541 in it (commodore.drive1541_code())"),
    ("c128_banks_test",          ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "a C128 program that changes the MMU's configuration"),

    # 6502 code: real programs
    ("os12",                     ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "MOS 1.20"),
    ("basic4",                   ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "BASIC 4"),
    ("dfs226",                   ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "DFS 2.26"),
    ("dfs226b",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "DFS with an artificially added move() just for testing"),
    ("anfs418",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Network filing system 4.18"),
    ("lisp406",                  ["acme", "beebasm", "baron", "64tass", "ca65"],"Lisp 4.06 (xa is excluded since it can't cope with: 'ldx #(>(LISPEN-LISVAL-1))+1'; for 64tass its '_AND' is 'AND_', since 64tass takes a label starting with '_' to be local)"),
    ("chuckie",                  ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Chuckie Egg"),
    ("planb",                    ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Plan B with the old style label_maker function"),
    ("planb_new_label_maker",    ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Plan B with a new style label_maker function"),
    ("starship",                 ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Starship Command"),
    ("open_roms_kernal",         ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the Kernal ROM of MEGA65's Open ROMs, a free replacement for the C64's"),
    ("open_roms_basic",          ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "the BASIC ROM of MEGA65's Open ROMs"),
    ("quikman2k8",               ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "Quikman 2K8, a VIC-20 game"),
    ("memory128",                ["acme", "beebasm", "baron", "xa", "64tass", "ca65"], "memory128, a C128 game for the 80 column screen"),
]

# The tests whose other outputs are also compared with known_good: the JSON
# (see docs/json-format.md), the symbol file and the cross-reference listing,
# as known_good/<test>_<assembler>.json, .symbols and .xref (which -m makes).
# (The JSON of every test is checked, see check_json(), and the symbol file
# made with beebasm, Baron, 64tass, ca65 or sjasmplus is checked against the
# labels that assembler reports, see run_test(), but these show any change
# to the outputs themselves.)
EXTRAS_KNOWN_GOOD = ["helloworld", "regression_tests", "move2", "local_labels", "subroutine_test", "test8080", "undocumented_8080", "prg_test", "undocumented_6502", "petscii_test", "c64_test", "c64_memory_test", "vic20_test", "c128_test", "test_z80", "undocumented_z80", "trace_z80", "state_z80", "spectrum_test", "branch_state", "redundant_z80"]

# The symbol file format made for each assembler's tests (py8dis's
# --symbols-format), so that each format is tested (see py8dis/symbols.py).
# Where run_test() checks the symbol file against the assembler's own
# labels, it reads the file in this format: beebasm's for beebasm, VICE's
# for Baron, 64tass and ca65, and plain for sjasmplus.
SYMBOLS_FORMATS = {"beebasm": "beebasm", "baron": "vice", "acme": "vice", "xa": "mame", "64tass": "vice", "ca65": "vice", "z88dk-8080": "plain", "z88dk": "plain", "sjasmplus": "plain"}

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
    ("entry_before_load",       "entry(): call load() first (it chooses the CPU)"),
    ("load_offset_past_end",    "load(&2000, 'orig/helloworld.orig'): the offset (28) is past the end of the file (28 bytes)"),
    ("load_length_past_end",    "load(&2000, 'orig/helloworld.orig'): the offset and length (20 + 10) run past the end of the file (28 bytes)"),
    ("load_bad_offset",         "load(&2000, 'orig/helloworld.orig'): the offset must be a whole number, 0 or more, not -1"),
    ("load_prg_too_short",      "load_prg('build/too_short.prg'): the file (2 bytes) is too short to be a PRG file (two bytes of load address, then the data)"),
    ("upper_case_os_calls_too_late", "config.set_upper_case_os_calls(): call it before acorn.bbc(), commodore.c64() etc., which name the OS calls"),
    ("c64_configuration_without_c64", "commodore.c64_configuration(): call commodore.c64() first"),
    ("c64_configuration_bad_address", "commodore.c64_configuration(): the addresses must be between 0 and $10000, not 74565"),
    ("c128_bank_without_c128",  "commodore.c128_bank(): call commodore.c128() first"),
    ("c128_bank_bad_bank",      "commodore.c128_bank(): the bank must be 0-15, not 16"),
    ("pet_80_columns_basic_2",  "commodore.pet(): only BASIC 4 PETs have 80 columns"),
    ("baron_reserved_label",    "Baron doesn't accept 'pi' as a label, since it's one of its constants: rename it"),
    ("tass64_local_label_name", "64tass takes a label starting with '_' to be local to the label before it, so '_count' can't be used: rename it"),
    ("ca65_register_label",     "ca65 doesn't accept 'x' as a label, since it's a register's name: rename it"),
    ("ca65_mnemonic_label",     "ca65 doesn't accept 'lax' as a label, since it's an instruction's mnemonic: rename it"),
    ("sjasmplus_register_label", "sjasmplus doesn't accept 'hl' as a label, since it's a register's name: rename it"),
    ("sjasmplus_operator_label", "sjasmplus doesn't accept 'LOW' as a label, since it's an operator's name: rename it"),
    ("sjasmplus_long_label",    "sjasmplus doesn't accept 'a_label_name_that_is_much_too_long_for_sjasmplus_which_allows_64_chars' as a label, since it's longer than 64 characters: rename it"),
    ("cpm_wrong_cpu",           "cpm.cpm(): call load(..., \"z80\") or load(..., \"8080\") first"),
    ("cpm_wrapper_without_cpm", "cpm.bdos_wrapper(): call cpm.cpm() first"),
    ("cpm_wrapper_bad_register", "cpm.bdos_wrapper($015a, 'b'): the register must be \"a\" or \"c\""),
    ("drive1541_bad_rom",       "commodore.drive1541(): rom must be one of '1541', '1541-ii', not '1571'"),
    ("drive1541_kernal_rom",    "commodore.kernal_rom(): the 1541 has no Kernal (use dos_rom())"),
    ("basic_program_1541",      "commodore.basic_program(): the 1541 has no BASIC, so give the program's address"),
    ("drive1541_code_in_drive", "commodore.drive1541_code(): this is already the 1541's disassembly (drive1541())"),
    ("snippet_bad_operand",     "register_snippet(): ASL can't have the operand '(foo),y': 'asl (foo),y'"),
    ("snippet_unindented_instruction", "register_snippet(): 'rts' at the start of a line is taken as a name (indent an instruction): 'rts'"),
    ("effect_register_without_anchor", "register_snippet(): a register line ('x = ...') needs an instruction line, to say where it applies"),
    ("effect_bad_value",        "register_snippet(): a value is a number, a name or '?': '[$70] = 1+2'"),
    ("effect_unbound_variable", "register_snippet(): the variable 'vec' isn't given its addresses (e.g. '[vec = $70 | $72]')"),
]

# Each warning test is (name, expected warning). The control file is
# python/warnings/<name>.py, which must run successfully (with beebasm) and
# give this warning (as one line of its error output).
WARNING_TESTS = [
    ("load_prg_file",           "warning: load(&07ff, 'build/load_prg_file.prg'): this looks like a Commodore PRG file, whose first two bytes are the address to load it at, not data; load_prg('build/load_prg_file.prg') loads it at that address without them"),
    ("jump_to_shared_address",  "warning: &1004: the jump or call to &8000 isn't traced, since more than one move puts code there (moves 1 and 2): trace the right one with entry() in a 'with' block for its move"),
    ("move_splits_data",        "warning: move boundary at binary address &3002 splits a classification"),
]

# The program each assembler needs: if it isn't on the PATH, the output
# isn't assembled (see run_test()). ca65 is run through cl65, which runs
# ca65 then its linker, ld65.
ASSEMBLER_PROGRAMS = {
    "acme":       "acme",
    "beebasm":    "beebasm",
    "baron":      "baron",
    "xa":         "xa",
    "64tass":     "64tass",
    "ca65":       "cl65",
    "z88dk-8080": "z88dk-z80asm",
    "z88dk":      "z88dk-z80asm",
    "sjasmplus":  "sjasmplus",
}

# Test scripts run as well by -c, when all the tests are run. Each passes if
# it exits with 0.
OTHER_TEST_SCRIPTS = ["session_tests.py", "render_tests.py"]

# The examples folder (main() makes it the current folder, so the paths
# below are relative to it), the py8dis being tested and the JSON schema
EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"
JSON_SCHEMA  = EXAMPLES_DIR.parent / "docs" / "py8dis-json.schema.json"


class Paths:
    """The files for one test with one assembler, relative to the examples
    folder:

    control_file and original are the control file and the program it
    disassembles. asm, json, py8dis_symbols and xref are what py8dis writes,
    and binary is what the assembler makes of the asm. known_good,
    known_good_json, known_good_symbols and known_good_xref are what they
    should be.

    beebasm_symbols and assembler_symbols are the labels the assembler
    itself writes (beebasm's, and Baron's, 64tass's, ld65's or sjasmplus's),
    to check py8dis's symbol file against. report and symbols are the
    assembler's report or listing and its own symbol file, made with -x
    (see assemble_command()). output_dir is the folder Baron saves the
    program in."""

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
        self.output_dir    = Path("build")      / f"{name}_{assembler}_output"


class Result:
    """The outcome of one test with one assembler."""
    def __init__(self, name, assembler):
        self.name = name
        self.assembler = assembler
        self.failure = None         # A message if the test failed
        self.notes = []             # e.g. "not assembled: acme not found"
        self.stderr = ""            # Anything py8dis printed to stderr (e.g. warnings)


def first_difference(file1, file2):
    """Describe the first line that differs between two text files (file1
    being what was made and file2 what was expected), for a failure
    message, or say that one is longer if every line they share is the
    same."""
    lines1 = file1.read_text(errors="replace").splitlines()
    lines2 = file2.read_text(errors="replace").splitlines()
    for i, (a, b) in enumerate(zip(lines1, lines2)):
        if a != b:
            return f"first difference at line {i+1}:\n      got:      {a.rstrip()}\n      expected: {b.rstrip()}"
    return f"files differ in length ({len(lines1)} lines vs {len(lines2)} lines expected)"


def assemble_command(assembler, p, make_extras):
    """Return the command line to assemble p.asm into p.binary (p being the
    test's Paths), as a list for subprocess.

    Each makes a plain binary (with no load address or header), to compare
    with the original. Where run_test()
    checks the assembler's own labels, the command also writes them
    (p.beebasm_symbols or p.assembler_symbols). With 'make_extras' (-x), it
    also writes the assembler's report or listing, and its own symbol file
    where it has one, for debugging. (Baron saves its binary in
    p.output_dir rather than p.binary: run_test() moves it.)"""
    if assembler == "acme":
        cmd = ["acme", "-o", str(p.binary)]
        if make_extras:
            cmd += ["--report", str(p.report), "-l", str(p.symbols)]
        return cmd + [str(p.asm)]
    if assembler == "beebasm":
        # (-d writes beebasm's own symbol dump, to check py8dis's against.
        # -v writes a listing to stdout, which run_test() saves as the
        # report with -x.)
        return ["beebasm", "-v", "-o", str(p.binary), "-i", str(p.asm), "-d", "-labels", str(p.beebasm_symbols)]
    if assembler == "baron":
        # (-p: write the program, as the file named in its section, in the
        # output folder. --symbols writes Baron's own symbols, as JSON, to
        # check py8dis's against. -v writes a listing, to stdout, which
        # run_test() saves as the report.)
        cmd = ["baron", "-p", str(p.output_dir), "--symbols", str(p.assembler_symbols)]
        if make_extras:
            cmd += ["-v"]
        return cmd + [str(p.asm)]
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
        # code "z88dk": it's the same assembler, told which CPU it is. -b
        # makes the binary.)
        cmd = ["z88dk-z80asm", "-m8080" if assembler == "z88dk-8080" else "-mz80", "-b"]
        if make_extras:
            # (-l and -s: z88dk-z80asm's listing and symbol files, which it
            # names after the asm file)
            cmd += ["-l", "-s"]
        return cmd + ["-o" + str(p.binary), str(p.asm)]
    if assembler == "sjasmplus":
        # (--raw: a plain binary. --syntax=w makes any warning an error, e.g.
        # the 'out (c),0' warning py8dis turns off. --sym writes sjasmplus's
        # own symbols, to check py8dis's against.)
        cmd = ["sjasmplus", "--nologo", "--msg=war", "--syntax=w", "--raw=" + str(p.binary), "--sym=" + str(p.assembler_symbols)]
        if make_extras:
            cmd += ["--lst=" + str(p.report)]
        return cmd + [str(p.asm)]
    raise ValueError(f"unknown assembler '{assembler}'")


# The validator json_validator() made: None until the first call, then the
# validator, or False if the jsonschema package isn't installed
_json_validator = None

def json_validator():
    """A validator for the JSON schema, or None if the jsonschema package
    isn't installed. The schema is read and the validator made on the first
    call, and kept for the others."""
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
    sample, for checking against the schema: the first two entries with
    each set of keys (and type), so that every kind of entry is checked.
    (Checking the whole of e.g. os12's JSON with jsonschema takes about a
    second, which for all the tests would double the time they take.)

    'doc' is the parsed JSON. If it isn't an object with both lists, it's
    returned as it is (for the schema to reject)."""
    def sample(entries):
        """The first two entries with each 'type' and set of keys."""
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
# expression.py). Each gives None where the value can't be worked out,
# since assemblers differ there (e.g. DIV and MOD of a negative number, or
# a shift of one), and then the value isn't checked.
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
    worked out (e.g. it uses a name, or a string written by the user).

    The tree's nodes are as docs/json-format.md describes: a number
    ('num'), a label ('label', its runtime address), a binary operator
    ('op', 'left' and 'right') or a unary one ('op' and 'arg'). Anything
    else, e.g. a name ('name') or a string from the control file ('raw'),
    has no value here, nor has an operator that isn't in the tables above
    (one a control file named itself, with make_op1() or make_op2())."""
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

# The hex dump in the asm, e.g. '   ; 2000: a2 00   ..' (or '//' for xa):
# group 1 is the binary address
HEX_DUMP = re.compile(r"\s*(?:;|//) ([0-9a-f]{4}): [0-9a-f]{2}")

def asm_lines_by_address(asm_path):
    """The asm's code lines (without the hex dump and anything after it,
    whitespace collapsed) for each binary address, from the hex dump, or None
    if there's no hex dump. (Comments, e.g. for overlapping instructions, are
    left out.)

    The result is a dictionary from each binary address to a list of the
    lines whose hex dump starts there."""
    result = {}
    for line in asm_path.read_text().splitlines():
        m = HEX_DUMP.search(line)
        if m and not line.lstrip().startswith((";", "//")):
            result.setdefault(int(m.group(1), 16), []).append(" ".join(line[:m.start()].split()))
    return result or None

# A plain label name, as opposed to an expression relative to a label (e.g.
# 'brkv+1')
SIMPLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

def check_json_labels(path, doc):
    """Check the JSON's labels agree with its items, returning a message
    describing the first problem, or None.

    'doc' is the parsed JSON, from the file 'path' (used in the messages).
    The checks are that:
    - the labels are in order of runtime address, each listed once;
    - each item's labels are inline names of the label at its runtime
      address, and each plain name its expressions use for a label is one
      of that label's names (or local names, or expressions);
    - the range boundaries are in order (by binary address, then move),
      each listed once, and their labels are inline names too;
    - each inline name of a label is defined by an item or range boundary
      at its address;
    - each reference to a label is from an item, at the runtime address
      that part of the item runs at."""
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
        """The label nodes in an expression tree."""
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
    first problem, or None.

    'doc' is the parsed JSON, from the file 'path', and 'asm' the text of
    the asm. The checks are that each comment's text is in the asm, each
    constant is defined on a line of the asm, each subroutine's name is a
    name of the label at its address, the memory regions are in order (by
    start address, and the longer first for the same start), and
    the heading each label's name is listed under is a memory region (or
    'Other', or one of the headings of its own a local name can have) that
    is in the asm."""
    def collapse(text):
        """The text without comment prefixes, and with whitespace
        collapsed, so that word wrapped comments can be found."""
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
    # banks', for the C128's names in other banks, 'Other memory
    # configurations', for the C64's names in other memory configurations,
    # and '1541 drive', for the 1541's names in drive code)
    own_headings = {"Other banks", "Other memory configurations", "1541 drive"}
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
    """The comment prefix the asm uses (';', or '//' for xa's, found by a
    line starting with it)."""
    return "//" if re.search(r"^//", asm, re.M) else ";"

def check_json(path, asm_path=None):
    """Check the JSON output (see docs/json-format.md), returning a message
    describing the first problem, or None.

    'path' is the JSON file, and 'asm_path' the asm py8dis wrote with it:
    the checks that compare the two are left out without it. The checks
    are, in order, that the JSON matches the schema (if jsonschema is
    installed), that the items cover the loaded data exactly, that the
    expressions' trees give their values, that the labels agree with the
    items (check_json_labels()), that the comments, constants, subroutines
    and memory regions agree with the asm (check_json_annotations()), and
    that each item's text matches the asm."""
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        return f"{path} isn't valid JSON: {e}"

    validator = json_validator()
    if validator is not None:
        # (The error with the first path in the JSON, whatever order
        # jsonschema finds them in)
        error = next(iter(sorted(validator.iter_errors(json_sample(doc)), key=lambda e: list(e.path))), None)
        if error is not None:
            return f"{path} doesn't match the schema at {'/'.join(str(x) for x in error.path) or 'the top'}: {error.message}"

    # The items must cover the loaded data exactly, each with the bytes loaded
    # there (later loads replacing earlier ones, as py8dis does). The loaded
    # files are read again here (from their names, relative to the examples
    # folder), from each load's offset.
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

    # Each expression's tree gives its value (where it can be worked out):
    # an instruction's operand, and a data item's expressions (None for a
    # value written without one). An operand's text must also be in the
    # instruction's text.
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
    # the binary address of each line): the asm has a line for each line of
    # the item's text, starting with it (since the asm's line can go on with
    # an inline comment)
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
    as a dictionary. This reads both beebasm's own dump (-d) and py8dis's
    symbol file in beebasm's format."""
    return {name: int(float(value)) for name, value in re.findall(r"'([^']*)':(-?[0-9.e+]+)L", text)}


def vice_symbols(text):
    """The symbols in a VICE label file ('al 00FFEE .name', or 64tass's 'al
    ffee .name'), as a dictionary. This reads py8dis's symbol file in VICE
    format, and 64tass's and ld65's own label files."""
    return {name: int(value, 16) for value, name in re.findall(r"^al ([0-9A-Fa-f]+) \.(\S+)$", text, re.MULTILINE)}


def plain_symbols(text):
    """The symbols in py8dis's plain symbol file format ('name = $ffee'), as
    a dictionary (to compare with sjasmplus's own)."""
    return {name: int(value, 16) for name, value in re.findall(r"^(\S+)\s*=\s*\$([0-9A-Fa-f]+)$", text, re.MULTILINE)}


def sjasmplus_symbols(text):
    """The symbols in sjasmplus's symbol file ('name: EQU 0x0000FFEE'), as a
    dictionary."""
    return {name: int(value, 16) for name, value in re.findall(r"^(\S+): EQU 0x([0-9A-Fa-f]+)$", text, re.MULTILINE)}


def baron_symbols(text):
    """The labels in Baron's symbol dump (JSON: each assembly's sections,
    each with its 'labels', not counting its 'assignments'), as a
    dictionary."""
    result = {}
    for assembly in json.loads(text)["assemblies"]:
        for section in assembly["sections"]:
            for name, symbol in section.get("labels", {}).items():
                result[name] = int(symbol["value"])
    return result


def run_test(name, assembler, options, env):
    """Run one test with one assembler, returning a Result.

    This does steps 1 to 4 described at the top of this file, stopping at
    the first failure. 'options' are the command-line options (from
    argparse), and 'env' the environment to run py8dis in (which finds the
    py8dis in this repository)."""
    result = Result(name, assembler)
    p = Paths(name, assembler)

    # 1. Run py8dis
    # (The control file reads the assembler and output options from its
    # command line, as when a user runs it. py8dis prints the asm, which is
    # saved here, unless it's written with -o.)
    # (For Baron, the asm is written with -o, since its output depends on the
    # asm file's name and folder: the name of the file Baron saves, and the
    # path of an included binary file, which Baron finds relative to the asm
    # file)
    output = ["-o", str(p.asm)] if assembler == "baron" else []
    proc = subprocess.run([sys.executable, str(p.control_file), "--" + assembler, "--json", str(p.json),
                           "--symbols", str(p.py8dis_symbols), "--symbols-format", SYMBOLS_FORMATS[assembler], "--xref", str(p.xref)] + output,
                          capture_output=True, text=True, env=env)
    result.stderr = proc.stderr.strip()
    if proc.returncode != 0:
        result.failure = "py8dis failed"
        return result
    if not output:
        p.asm.write_text(proc.stdout)

    # 2. Check the asm against known good, then the JSON, then (for the
    # tests in EXTRAS_KNOWN_GOOD) the other outputs against known good
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

    # (Baron's output folder starts empty, so that the file it saves is the
    # only one there)
    if assembler == "baron":
        shutil.rmtree(p.output_dir, ignore_errors=True)
        p.output_dir.mkdir(parents=True)
    proc = subprocess.run(assemble_command(assembler, p, options.make_extras), capture_output=True, text=True)
    if assembler in ("beebasm", "baron") and options.make_extras:
        p.report.write_text(proc.stdout)
    if proc.returncode != 0:
        result.failure = f"{program} failed:\n" + (proc.stderr or proc.stdout).strip()
        return result
    if assembler == "baron":
        if proc.stderr.strip():
            # (e.g. a warning that nothing was saved)
            result.failure = f"{program} gave a warning:\n" + proc.stderr.strip()
            return result
        # (The one file Baron saved, named in the section)
        saved = list(p.output_dir.iterdir())
        if len(saved) != 1:
            result.failure = f"{program} saved {len(saved)} files in {p.output_dir}, not one"
            return result
        shutil.move(str(saved[0]), str(p.binary))
    if assembler == "ca65" and "Warning" in proc.stderr:
        # (e.g. "Didn't use zeropage addressing", for a zero page label used
        # before it's defined, which is assembled with the wrong bytes)
        result.failure = f"{program} gave a warning:\n" + proc.stderr.strip()
        return result
    if not filecmp.cmp(p.binary, p.original, shallow=False):
        result.failure = f"assembled binary {p.binary} differs from {p.original}"
        return result

    # Then the labels the assembler reports are checked against py8dis's
    # symbol file (in the format SYMBOLS_FORMATS gives for the assembler).
    # This shows that the symbol file gives each label the address it has
    # in the asm. (acme, xa and z88dk-z80asm aren't checked.)

    # beebasm's own symbols (its labels, defined as '.name') must all be in
    # py8dis's symbol file, with the same values
    if assembler == "beebasm":
        ours = beebasm_symbols(p.py8dis_symbols.read_text())
        for symbol, value in beebasm_symbols(p.beebasm_symbols.read_text()).items():
            if ours.get(symbol) != value:
                result.failure = f"beebasm gives {symbol} the value {value}, but py8dis's symbol file {p.py8dis_symbols} gives {ours.get(symbol)}"
                return result

    # 64tass's and ld65's own symbols (their labels, not those defined with
    # '='), both in VICE's format, must all be in py8dis's symbol file, with
    # the same values
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

    # Baron's own symbols (its labels, not those defined with '=') must all be
    # in py8dis's symbol file, with the same values
    if assembler == "baron":
        ours = vice_symbols(p.py8dis_symbols.read_text())
        for symbol, value in baron_symbols(p.assembler_symbols.read_text()).items():
            if value == 0x10000 and symbol not in ours:
                # (A label at &10000, after code at the top of memory, which
                # py8dis's VICE symbols leave out)
                continue
            if ours.get(symbol) != value:
                result.failure = f"{assembler} gives {symbol} the value {value}, but py8dis's symbol file {p.py8dis_symbols} gives {ours.get(symbol)}"
                return result

    # sjasmplus's own symbols (its labels, not those defined with 'equ') must
    # all be in py8dis's symbol file, with the same values
    if assembler == "sjasmplus":
        ours = plain_symbols(p.py8dis_symbols.read_text())
        asm_text = p.asm.read_text()
        for symbol, value in sjasmplus_symbols(p.assembler_symbols.read_text()).items():
            # (As for 64tass, a name defined with 'equ' in a control file's
            # own text isn't in py8dis's symbol file)
            if symbol not in ours and re.search(r"^" + re.escape(symbol) + r"\s+equ\b", asm_text, re.MULTILINE | re.IGNORECASE):
                continue
            if ours.get(symbol) != value:
                result.failure = f"{assembler} gives {symbol} the value {value}, but py8dis's symbol file {p.py8dis_symbols} gives {ours.get(symbol)}"
                return result

    # 4. Make known good (only reached once the binary has been checked)
    if options.make_known_good:
        shutil.copy2(p.asm, p.known_good)
        if name in EXTRAS_KNOWN_GOOD:
            shutil.copy2(p.json, p.known_good_json)
            shutil.copy2(p.py8dis_symbols, p.known_good_symbols)
            shutil.copy2(p.xref, p.known_good_xref)
        result.notes.append("made known good")
    return result


def run_error_test(name, expected, env):
    """Run one error test, returning a Result.

    It runs python/errors/<name>.py with --beebasm, in the environment
    'env', and passes if that fails (a non-zero exit code) with 'expected'
    as the last line it writes to stderr (ignoring blank lines)."""
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
    """Run one warning test, returning a Result.

    It runs python/warnings/<name>.py with --beebasm, in the environment
    'env', and passes if that succeeds and 'expected' is one of the lines it
    writes to stderr (ignoring the spaces at either end). Its asm, printed
    to stdout, isn't checked."""
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
    """Read the command line (see the top of this file), run the tests it
    chooses, print a line for each, then the totals, and exit with 1 if any
    failed."""
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

    # (The paths in Paths, and the file names in the control files, are
    # relative to the examples folder)
    os.chdir(EXAMPLES_DIR)
    Path("build").mkdir(exist_ok=True)
    Path("known_good").mkdir(exist_ok=True)

    # Use the py8dis in this repository (the control files import its
    # modules, e.g. 'from commands import *', so it goes first on the
    # PYTHONPATH)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(PY8DIS_DIR)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))

    # The tests to run: each test with each of its assemblers, then the error
    # and warning tests (which are left out with -a)
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
    # (The width of the column of names in the report)
    width = max([len(f"{n}_{a}") for n, a in jobs] + [len(f"{n}_error") for n, _ in error_jobs] + [len(f"{n}_warning") for n, _ in warning_jobs], default=0) + 2
    # The other test scripts, when checking all the tests. These start first
    # since the session tests take longest.
    other_scripts = OTHER_TEST_SCRIPTS if (options.check_disassembly and not options.tests and not options.assemblers) else []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, options.jobs)) as executor:
        other_futures = [executor.submit(subprocess.run, [sys.executable, script], capture_output=True, text=True, env=env)
                         for script in other_scripts]
        futures = [executor.submit(run_test, name, assembler, options, env) for name, assembler in jobs]
        futures += [executor.submit(run_error_test, name, expected, env) for name, expected in error_jobs]
        # ('jobs' gets everything that's run, so that its length is the
        # number of tests in the totals at the end)
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
                # (Its output, without the session tests' lines for the
                # checks that passed, or py8dis's warnings)
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
            # (Anything py8dis wrote to stderr, e.g. warnings, is shown under
            # the test's line, whether or not it passed)
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
