#!/usr/bin/env python3
"""
Run the py8dis example tests.

For each test and assembler:
  1. Run the control file in python/ to produce build/<test>_<assembler>.asm
  2. With -c, check that the asm is identical to known_good/<test>_<assembler>.asm
  3. If the assembler is installed, assemble the asm and check the binary is
     identical to orig/<test>.orig. If the assembler isn't installed this step
     is skipped, but the check in step 2 still happens (so e.g. CI can run
     without any assemblers installed).
  4. With -m, copy the asm to known_good (only once the binary has been checked)

Tests run in parallel. Examples:

  ./run_tests.py -c                     # run and check all tests
  ./run_tests.py -c move move2          # just these tests
  ./run_tests.py -c -a acme             # just the acme versions of the tests
  ./run_tests.py -m regression_tests    # make known good files
"""

import argparse
import concurrent.futures
import filecmp
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

    # 6502 code: tests
    ("include_binary_file",      ["acme", "beebasm", "xa"],    "tests for including a binary file"),
    ("char_literals",            ["acme", "beebasm", "xa"],    "tests for all character literals"),
    ("align_test",               ["acme", "beebasm", "xa"],    "tests for formatting"),
    ("cycles",                   ["acme", "beebasm", "xa"],    "cycle counts for branches near page boundaries"),
    ("string_stuff1",            ["acme", "beebasm"],          "xa omitted since it can't do string constants e.g. 'page = \"1900\"'"),
    ("string_stuff2",            ["beebasm"],                  "testing the beebasm specific expression 'STR$~(page)'"),
    ("string_stuff3",            ["acme", "beebasm", "xa"],    "testing py8dis string commands"),
    ("moving1",                  ["acme", "beebasm", "xa"],    "tests for the move() command"),
    ("moving2",                  ["acme", "beebasm", "xa"],    "tests for the move() command"),
    ("moving3",                  ["acme", "beebasm", "xa"],    "tests for the move() command"),
    ("helloworld",               ["acme", "beebasm", "xa"],    "the basic hello world test"),
    ("local_labels",             ["acme", "beebasm", "xa"],    "labels defined as local to one move region"),
    ("move",                     ["acme", "beebasm", "xa"],    "a move() test"),
    ("move2",                    ["acme", "beebasm", "xa"],    "another move() test"),
    ("move2_legacy_label_maker", ["acme", "beebasm", "xa"],    "move2 with a legacy label maker hook choosing a move"),
    ("move_from_top_of_memory",  ["acme", "beebasm", "xa"],    "a move() whose source ends at &10000"),
    ("move_to_top_of_memory",    ["acme", "beebasm", "xa"],    "a move() whose destination ends at &10000"),
    ("split",                    ["acme", "beebasm", "xa"],    "loads *two* binary files to disassemble"),
    ("subroutine_test",          ["acme", "beebasm", "xa"],    "demonstrates the use of the subroutine() command"),
    ("regression_tests",         ["acme", "beebasm", "xa"],    "regression tests for fixed bugs"),
    ("expressions",              ["acme", "beebasm", "xa"],    "how expressions are bracketed for each assembler"),
    ("acorn_os_calls",           ["acme", "beebasm", "xa"],    "test all the os calls for acorn machines"),

    # 6502 code: real programs
    ("os12",                     ["acme", "beebasm", "xa"],    "MOS 1.20"),
    ("basic4",                   ["acme", "beebasm", "xa"],    "BASIC 4"),
    ("dfs226",                   ["acme", "beebasm", "xa"],    "DFS 2.26"),
    ("dfs226b",                  ["acme", "beebasm", "xa"],    "DFS with an artificially added move() just for testing"),
    ("anfs418",                  ["acme", "beebasm", "xa"],    "Network filing system 4.18"),
    ("lisp406",                  ["acme", "beebasm"],          "Lisp 4.06 (xa is excluded since it can't cope with: 'ldx #(>(LISPEN-LISVAL-1))+1')"),
    ("chuckie",                  ["acme", "beebasm", "xa"],    "Chuckie Egg"),
    ("planb",                    ["acme", "beebasm", "xa"],    "Plan B with the old style label_maker function"),
    ("planb_new_label_maker",    ["acme", "beebasm", "xa"],    "Plan B with a new style label_maker function"),
    ("starship",                 ["acme", "beebasm", "xa"],    "Starship Command"),
]

# The program each assembler needs
ASSEMBLER_PROGRAMS = {
    "acme":       "acme",
    "beebasm":    "beebasm",
    "xa":         "xa",
    "z88dk-8080": "z88dk-z80asm",
}

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"


class Paths:
    def __init__(self, name, assembler):
        self.control_file  = Path("python")     / f"{name}.py"
        self.original      = Path("orig")       / f"{name}.orig"
        self.asm           = Path("build")      / f"{name}_{assembler}.asm"
        self.binary        = Path("build")      / f"{name}_{assembler}.dat"
        self.known_good    = Path("known_good") / f"{name}_{assembler}.asm"
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
        return ["beebasm", "-v", "-o", str(p.binary), "-i", str(p.asm)]
    if assembler == "xa":
        cmd = ["xa", str(p.asm), "-o", str(p.binary)]
        if make_extras:
            cmd += ["-l", str(p.symbols), "-P", str(p.report)]
        return cmd
    if assembler == "z88dk-8080":
        cmd = ["z88dk-z80asm", "-m8080", "-b"]
        if make_extras:
            cmd += ["-l", "-s"]
        return cmd + ["-o" + str(p.binary), str(p.asm)]
    raise ValueError(f"unknown assembler '{assembler}'")


def run_test(name, assembler, options, env):
    """Run one test with one assembler, returning a Result."""
    result = Result(name, assembler)
    p = Paths(name, assembler)

    # 1. Run py8dis
    proc = subprocess.run([sys.executable, str(p.control_file), "--" + assembler],
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
    if not filecmp.cmp(p.binary, p.original, shallow=False):
        result.failure = f"assembled binary {p.binary} differs from {p.original}"
        return result

    # 4. Make known good
    if options.make_known_good:
        shutil.copy2(p.asm, p.known_good)
        result.notes.append("made known good")
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

    known_names = [name for name, _, _ in TESTS]
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

    start = time.time()
    failures = 0
    width = max((len(f"{n}_{a}") for n, a in jobs), default=0) + 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, options.jobs)) as executor:
        futures = [executor.submit(run_test, name, assembler, options, env) for name, assembler in jobs]
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
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
