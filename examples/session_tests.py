#!/usr/bin/env python3
"""
Tests for py8dis sessions (see py8dis/session.py), run by run_tests.py -c.

All the state of a disassembly belongs to a session, so these run several
disassemblies in this one process, using py8dis as a library (with
use_command_line(False)), and check:

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

Usage: ./session_tests.py      (exits with 1 if anything fails)
"""

import contextlib
import enum
import io
import os
import runpy
import subprocess
import sys
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
]

# Module level names that are allowed to change
ALLOWED_TO_CHANGE = {("session", "_current"), ("session", "_use_command_line")}


def py8dis_modules():
    """The py8dis modules imported so far, by name."""
    result = {}
    for name, m in list(sys.modules.items()):
        f = getattr(m, "__file__", None)
        if f and Path(f).resolve().parent == PY8DIS_DIR:
            result[name] = m
    return result

def fingerprint(value, seen, depth=0):
    """A comparable summary of a value (and what it contains)."""
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
    attribute, by the py8dis modules."""
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
    pass

def run_control_file(name, assembler, stop_before_go=False):
    """Run a control file in a new session, returning its output. If
    stop_before_go, return the session and what the control file printed
    before its go() instead."""
    import commands
    import session

    s = session.new_session(assembler=assembler)
    real_go = commands.go
    def deferred_go(*args, **kwargs):
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
    return out.getvalue()

def go_in(s):
    """Run go() in the given session, returning its output."""
    import commands
    import session
    session.set_current(s)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        commands.go()
    return out.getvalue()

def check(results, label, output, name, assembler):
    expected = (EXAMPLES_DIR / "known_good" / f"{name}_{assembler}.asm").read_text()
    ok = (output == expected)
    if not ok:
        a, b = output.splitlines(), expected.splitlines()
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        label += f": differs from known_good at line {i+1}\n      got:      {a[i] if i < len(a) else '<end>'}\n      expected: {b[i] if i < len(b) else '<end>'}"
    results.append((label, ok))


def main():
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
    # disassemblies below.)
    import_checks = {}
    for f in sorted(PY8DIS_DIR.glob("*.py")):
        code = "import sys, {0}, session; sys.exit(0 if session._current is None else 2)".format(f.stem)
        import_checks[f.stem] = subprocess.Popen([sys.executable, "-c", code], cwd=PY8DIS_DIR,
                                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    # 1. Interleaved
    for (name_a, asm_a), (name_b, asm_b) in INTERLEAVED:
        session_a, printed_a = run_control_file(name_a, asm_a, stop_before_go=True)
        check(results, f"{name_b}_{asm_b} (while {name_a} waits)", run_control_file(name_b, asm_b), name_b, asm_b)
        check(results, f"{name_a}_{asm_a} (after {name_b})", printed_a + go_in(session_a), name_a, asm_a)

    # 2. No state at module level
    after = module_state()
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    results.append(("no state kept at module level" + ("".join(f"\n      changed: {m}.{n}" for m, n in changed)), not changed))

    # 3. (The results)
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
