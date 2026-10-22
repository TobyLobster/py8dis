"""
The session: the state of one disassembly.

Commands act on the current session, returned by current(). The first time
it's needed, a default session is made using the options on the command line
(e.g. --acme), unless use_command_line(False) has been called. reset() starts
a new session.

Nothing should keep a reference to the session's state (e.g. its settings)
from one call to the next, since it will be out of date after a reset.

(This is being introduced in steps: so far the session holds the settings,
the assembler, the output filenames, the memory and the moves. The rest of the state is still held
by the individual modules. See claude/architecture-notes-2026-10-21.md in the
project.)
"""

import argparse

import config
import utils

class Session:
    def __init__(self, *, assembler="beebasm", lower_case=True, asm_filename=None):
        """Make a new session.

        'assembler' is the assembler to produce output for: its name (beebasm,
        acme, xa or z88dk-8080) or an assembler object.

        'lower_case' is True for lower case output, False for upper case.

        'asm_filename' is the file to write the disassembly to, or None to
        print it."""

        # (These modules are imported here rather than at the top of this
        # file, since they import this module themselves.)
        import memorymanager
        import movemanager

        self.settings = config.Settings()
        self.settings.lower_case = lower_case
        self.assembler = make_assembler(assembler) if utils.is_string_type(assembler) else assembler

        # Where go() writes the disassembly (None means print it)
        self.asm_filename = asm_filename

        # The filename the assembler saves the assembled binary to, for
        # assemblers that support it (see commands.set_output_filename())
        self.output_filename = None

        self.memory = memorymanager.Memory()
        self.moves  = movemanager.Moves()

def make_assembler(name):
    """Make a new assembler object, given the assembler's name."""

    # (The assembler modules are only imported when needed.)
    if name == "beebasm":
        import beebasm
        return beebasm.Beebasm()
    if name == "acme":
        import acme
        return acme.Acme()
    if name == "xa":
        import xa
        return xa.Xa()
    if name == "z88dk-8080":
        import z88dk_8080
        return z88dk_8080.Z88DK()
    utils.die("Unknown assembler '{0}' (expected beebasm, acme, xa or z88dk-8080)".format(name))


# The command line

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--beebasm", action="store_true", help="generate beebasm-style output (default)")
parser.add_argument("-a", "--acme", action="store_true", help="generate acme-style output")
parser.add_argument("-x", "--xa", action="store_true", help="generate xa-style output")
parser.add_argument("-8", "--z88dk-8080", action="store_true", help="generate z88dk style output for the 8080 processor")
parser.add_argument("-l", "--lower", action="store_true", help="generate lower-case output (default)")
parser.add_argument("-u", "--upper", action="store_true", help="generate upper-case output")
parser.add_argument("-o", "--output", help="output asm file")

def options_from_command_line():
    """Read the command line, returning the options for a new session."""

    # (Other arguments are allowed, for the control file's own use.)
    args = parser.parse_known_args()[0]

    assembler_count = sum(1 for x in (args.beebasm, args.acme, args.xa, args.z88dk_8080) if x)
    if assembler_count > 1:
        utils.die("--beebasm, --acme, --xa and --z88dk-8080 arguments are incompatible")
    if args.lower and args.upper:
        utils.die("--lower and --upper arguments are incompatible")

    if args.acme:
        assembler = "acme"
    elif args.xa:
        assembler = "xa"
    elif args.z88dk_8080:
        assembler = "z88dk-8080"
    else:
        assembler = "beebasm"

    return { "assembler": assembler, "lower_case": not args.upper, "asm_filename": args.output }


# The current session

_current = None
_current_used_command_line = False     # Was the current session made using the command line?
_use_command_line = True               # See use_command_line()

def current():
    """The session that commands act on. The default session is made on
    first use."""
    if _current is None:
        new_session()
    return _current

def new_session(**options):
    """Start a new session (this is what reset() does), and return it.

    The options are as for Session(). If none are given, they come from the
    command line (unless use_command_line(False) has been called)."""

    global _current, _current_used_command_line
    _current_used_command_line = (not options) and _use_command_line
    if _current_used_command_line:
        options = options_from_command_line()
    _current = Session(**options)
    return _current

def use_command_line(enabled=True):
    """Choose whether new sessions use the options on the command line (e.g.
    --acme). This is on by default. A program that uses py8dis as a library,
    and has its own command line, can turn it off. This must be done before
    any other command."""

    global _use_command_line
    if not enabled and _current is not None and _current_used_command_line:
        utils.die("use_command_line(False) must be called before any other command (the command line has already been read)")
    _use_command_line = enabled
