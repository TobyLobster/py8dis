#!/usr/bin/env python3
"""
Session tests

Tests for py8dis sessions (see py8dis/session.py), run by run_tests.py -c
when all the tests are run.

All the state of a disassembly (its memory, labels, classifications,
settings and so on) belongs to a session, so that a program can use py8dis
as a library and make several disassemblies in one process. These tests do
that: they run control files from python/ in this one process, each in a
new session made with session.new_session() (with use_command_line(False),
so that py8dis doesn't read this script's command line), and check:

  1. Disassemblies can be interleaved: one control file runs up to its go(),
     then another runs completely in a new session, then the first session is
     made current again and its go() runs. Both outputs must match
     known_good, as when each control file is run alone.

  2. No py8dis module keeps any state of its own: the values held at module
     level (and in class attributes) are the same after all the disassemblies
     as before them. The session module's pointer to the current session is
     the only exception.

  3. Each py8dis module can be imported on its own, in a new process, and
     importing it has no side effects: in particular no session is made, so
     the command line isn't read.

Usage: ./session_tests.py      (there are no options; it prints a line for
                                each check, and exits with 1 if anything
                                fails)

The outputs are compared with the known_good/ files that run_tests.py
checks. Baron's output depends on the asm file's name and folder, so it's
written to a file of the same name as run_tests.py's, but in a temporary
folder beside build/ (at the same depth, so the paths in it are the same),
which is removed afterwards. (run_tests.py runs this script at the same
time as its own tests, so writing to build/ too could clash with them.)

To check another disassembly in 1, add a pair to INTERLEAVED (its
known_good file must exist already). Check 3 covers every module in
py8dis/ with no change here. A value at module level that's allowed to
change (as the session module's pointer to the current session must) goes
in ALLOWED_TO_CHANGE.
"""

import contextlib
import enum
import io
import os
import runpy
import subprocess
import sys
import tempfile
import types
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
PY8DIS_DIR   = EXAMPLES_DIR.parent / "py8dis"

# Pairs of (control file, assembler) to interleave: the first runs up to its
# go(), then the second runs completely, then the first's go() runs. These
# cover each CPU and assembler, moves, acorn.py and its snippets, local labels
# and both kinds of label maker hook, while keeping the time taken down (os12
# and chuckie take a second or two each; the others are quick).
INTERLEAVED = [
    (("os12",             "acme"), ("test8080",                 "z88dk-8080")),
    (("chuckie",          "xa"),   ("move2_legacy_label_maker", "beebasm")),
    (("regression_tests", "acme"), ("local_labels",             "beebasm")),
    (("c128_test",        "64tass"), ("helloworld",             "acme")),
    (("pet4_test",        "ca65"),   ("subroutine_test",        "xa")),
    (("trace_z80",        "z88dk"),  ("undocumented_8080",      "z88dk-8080")),
    (("spectrum_test",    "sjasmplus"), ("undocumented_z80",    "z88dk")),
    (("include_binary_file", "baron"), ("planb",                "beebasm")),
]

# The temporary folder for Baron's output (see baron_asm_filename()), which
# main() makes
baron_dir = None

# Module level names that are allowed to change, as (module, name): the
# session module's pointer to the current session, and its setting from
# use_command_line()
ALLOWED_TO_CHANGE = {("session", "_current"), ("session", "_use_command_line")}


def py8dis_modules():
    """The py8dis modules imported so far, by name: those whose file is in
    the py8dis folder itself."""
    result = {}
    for name, m in list(sys.modules.items()):
        f = getattr(m, "__file__", None)
        if f and Path(f).resolve().parent == PY8DIS_DIR:
            result[name] = m
    return result

def fingerprint(value, seen, depth=0):
    """A comparable summary of a value (and what it contains).

    Plain values (None, numbers, strings and bytes) are themselves;
    functions, methods, classes and modules are their names; lists, tuples
    and dictionaries are summaries of their contents (a dictionary's sorted
    by key); sets are their contents' repr()s, sorted; and other objects
    are summaries of their attributes, or their repr() if they have no
    __dict__. Each but a plain value comes with its type's name.

    'seen' is the ids of the values this one is inside, so that a value
    that contains itself isn't followed round for ever; 'depth' is how deep
    inside the first value this is, and a value more than 8 levels down
    isn't followed either. Both give ('<seen>', its type's name)."""
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, (types.FunctionType, types.BuiltinFunctionType, types.MethodType, type, types.ModuleType)):
        return ("<" + type(value).__name__ + ">", getattr(value, "__qualname__", getattr(value, "__name__", "?")))
    if id(value) in seen or depth > 8:
        return ("<seen>", type(value).__name__)
    seen = seen | {id(value)}
    if isinstance(value, (list, tuple)):
        return (type(value).__name__, tuple(fingerprint(x, seen, depth + 1) for x in value))
    if isinstance(value, dict):
        return (type(value).__name__, tuple(sorted(((repr(k), fingerprint(v, seen, depth + 1)) for k, v in value.items()), key=lambda kv: kv[0])))
    if isinstance(value, (set, frozenset)):
        return (type(value).__name__, tuple(sorted(repr(x) for x in value)))
    if hasattr(value, "__dict__"):
        return (type(value).__name__, fingerprint(vars(value), seen, depth + 1))
    return (type(value).__name__, repr(value))

def module_state():
    """A fingerprint of every value held at module level, or in a class
    attribute, by the py8dis modules, as a dictionary from (module name,
    name) to the value's fingerprint(). For a class attribute the name is
    'class.attribute'.

    Imported modules, enums, the names in ALLOWED_TO_CHANGE and names
    starting with '__' are left out, and so are methods and properties."""
    state = {}
    for mod_name, m in py8dis_modules().items():
        for name, value in vars(m).items():
            if name.startswith("__") or (mod_name, name) in ALLOWED_TO_CHANGE:
                continue
            if isinstance(value, types.ModuleType):
                continue
            if isinstance(value, type) and issubclass(value, enum.Enum):
                continue
            if isinstance(value, type):
                # Class attributes (but not methods)
                for attr, v in vars(value).items():
                    if not attr.startswith("__") and not callable(v) and not isinstance(v, (staticmethod, classmethod, property)):
                        state[(mod_name, name + "." + attr)] = fingerprint(v, frozenset())
                continue
            state[(mod_name, name)] = fingerprint(value, frozenset())
    return state


class DeferredGo(Exception):
    """Raised by the stand-in for go() that run_control_file() uses, to stop
    a control file where it calls go()."""
    pass

def run_control_file(name, assembler, stop_before_go=False):
    """Run a control file in a new session, returning its output. If
    stop_before_go, return the session and what the control file printed
    before its go() instead.

    The control file python/<name>.py is run as a script (with runpy), and
    acts on the new session, since that's the current one. To stop it at
    go(), commands.go is replaced while it runs by a function that raises
    DeferredGo: the control file's 'from commands import *' picks up that
    function. (So anything after go() in the control file isn't run, even
    when go_in() runs go() later.) What it prints (the asm, except for
    Baron) is captured rather than printed."""
    import commands
    import session

    # (Baron's output is written to a file, as run_tests.py does, since it
    # depends on the asm file's name and folder)
    asm_filename = baron_asm_filename(name, assembler)
    s = session.new_session(assembler=assembler, asm_filename=asm_filename)
    real_go = commands.go
    def deferred_go(*args, **kwargs):
        """Stop the control file (see DeferredGo)."""
        raise DeferredGo()
    if stop_before_go:
        commands.go = deferred_go
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            runpy.run_path(str(EXAMPLES_DIR / "python" / (name + ".py")), run_name="__main__")
    except DeferredGo:
        return s, out.getvalue()
    finally:
        commands.go = real_go
    return Path(asm_filename).read_text() if asm_filename else out.getvalue()

def go_in(s):
    """Run go() in the given session, returning its output. This makes it
    the current session, which it stays afterwards."""
    import commands
    import session
    session.set_current(s)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        commands.go()
    return Path(s.asm_filename).read_text() if s.asm_filename else out.getvalue()

def baron_asm_filename(name, assembler):
    """For Baron, the asm file to write, else None (for the asm to be
    printed). Baron's output depends on the asm file's name and folder, so
    for it to be the same as known_good, the file has the name run_tests.py
    gives it, in a folder at the same depth as build/ (baron_dir, rather
    than build/ itself, where run_tests.py may be writing the same file at
    the same time)."""
    return str(Path(baron_dir) / f"{name}_{assembler}.asm") if assembler == "baron" else None

def check(results, label, output, name, assembler):
    """Compare the asm 'output' with known_good/<name>_<assembler>.asm, and
    add (label, whether it's the same) to 'results'. If it isn't, the label
    says where they first differ."""
    expected = (EXAMPLES_DIR / "known_good" / f"{name}_{assembler}.asm").read_text()
    ok = (output == expected)
    if not ok:
        a, b = output.splitlines(), expected.splitlines()
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        label += f": differs from known_good at line {i+1}\n      got:      {a[i] if i < len(a) else '<end>'}\n      expected: {b[i] if i < len(b) else '<end>'}"
    results.append((label, ok))


def main():
    """Run the checks described at the top of this file, print a line for
    each, then the totals, and return the exit code: 1 if any failed, else
    0. (Baron's output goes in a temporary folder in the examples folder,
    removed afterwards: see baron_asm_filename().)"""
    global baron_dir
    with tempfile.TemporaryDirectory(prefix="session_tests_", dir=EXAMPLES_DIR) as baron_dir:
        return run_checks()

def run_checks():
    """main()'s checks."""
    # (The control files' file names are relative to the examples folder,
    # and they import py8dis's modules by name, e.g. 'from commands import
    # *')
    os.chdir(EXAMPLES_DIR)
    sys.path.insert(0, str(PY8DIS_DIR))
    sys.argv = [sys.argv[0]]            # (no assembler options on the command line)

    import commands
    commands.use_command_line(False)

    # Import all of py8dis first, so the state of every module is checked
    import importlib
    for f in sorted(PY8DIS_DIR.glob("*.py")):
        importlib.import_module(f.stem)

    before = module_state()
    results = []

    # 3. Each module imports on its own, with no session made. (These are
    # started first, in other processes, while this one does the
    # disassemblies below.) Each process runs in the py8dis folder, so it
    # imports py8dis's modules, and exits with 2 if importing the module
    # made a session, or with another non-zero code (and an error message)
    # if importing it failed.
    import_checks = {}
    for f in sorted(PY8DIS_DIR.glob("*.py")):
        code = "import sys, {0}, session; sys.exit(0 if session._current is None else 2)".format(f.stem)
        import_checks[f.stem] = subprocess.Popen([sys.executable, "-c", code], cwd=PY8DIS_DIR,
                                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # 1. Interleaved: the first control file stops at go(), the second runs
    # completely, then the first's go() runs. (The first's output is what it
    # printed before go(), then what go() gives.)
    for (name_a, asm_a), (name_b, asm_b) in INTERLEAVED:
        session_a, printed_a = run_control_file(name_a, asm_a, stop_before_go=True)
        check(results, f"{name_b}_{asm_b} (while {name_a} waits)", run_control_file(name_b, asm_b), name_b, asm_b)
        check(results, f"{name_a}_{asm_a} (after {name_b})", printed_a + go_in(session_a), name_a, asm_a)

    # 2. No state at module level: every value module_state() covers is the
    # same as before the disassemblies
    after = module_state()
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    results.append(("no state kept at module level" + ("".join(f"\n      changed: {m}.{n}" for m, n in changed)), not changed))

    # 3. (The results: one check for all the modules, listing any that
    # failed)
    problems = []
    for module_name, proc in import_checks.items():
        output = proc.communicate()[0].strip()
        if proc.returncode == 2:
            problems.append(f"\n      importing {module_name} makes a session")
        elif proc.returncode != 0:
            problems.append(f"\n      importing {module_name} fails: {output.splitlines()[-1] if output else '?'}")
    results.append((f"each of the {len(import_checks)} modules imports on its own, with no side effects" + "".join(problems), not problems))

    failures = 0
    for label, ok in results:
        print(f"  {'passed' if ok else 'FAILED'}: {label}")
        failures += not ok
    print(f"session tests: {len(results) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
