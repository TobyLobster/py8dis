"""
The session: the state of one disassembly.

Commands act on the current session, returned by current(). The first time
it's needed, a default session is made using the options on the command line
(e.g. --acme), unless use_command_line(False) has been called. reset() starts
a new session.

Nothing should keep a reference to the session's state (e.g. its settings)
from one call to the next, since it will be out of date after a reset.

(See "One state object instead of module-level globals" in
claude/architecture-notes-2026-10-21.md in the project.)
"""

import argparse

import config
import utils

class Session:
    def __init__(self, *, assembler="beebasm", lower_case=True, asm_filename=None, json_filename=None,
                 symbols_filename=None, symbols_format="plain", xref_filename=None):
        """Make a new session.

        'assembler' is the assembler to produce output for: its name (beebasm,
        acme, xa, 64tass, ca65 or z88dk-8080) or an assembler object.

        'lower_case' is True for lower case output, False for upper case.

        'asm_filename' is the file to write the disassembly to, or None to
        print it.

        'json_filename' is a file to write the disassembly to as JSON as well
        (see docs/json-format.md), or None.

        'symbols_filename' is a file to write the labels and their addresses
        to as well (a symbol file, see symbols.py), in 'symbols_format':
        'plain', 'vice', 'beebasm' or 'mame'. 'xref_filename' is a file to
        write a cross-reference listing to as well. None for neither."""

        # (These modules are imported here rather than at the top of this
        # file, since they import this module themselves.)
        import classification
        import disassembly
        import labelmanager
        import memorymanager
        import movemanager
        import snippets6502
        import trace

        self.settings = config.Settings()
        self.settings.lower_case = lower_case
        self.assembler = make_assembler(assembler) if utils.is_string_type(assembler) else assembler

        # Where go() writes the disassembly (None means print it)
        self.asm_filename = asm_filename

        # Where go() writes the disassembly as JSON as well (None means it
        # doesn't), see jsonoutput.py
        self.json_filename = json_filename

        # Where go() writes a symbol file and a cross-reference listing as
        # well (None means it doesn't), see symbols.py
        import symbols
        if symbols_format not in symbols.FORMATS:
            utils.die("Unknown symbol file format '{0}' (expected {1})".format(symbols_format, ", ".join(symbols.FORMATS)))
        self.symbols_filename = symbols_filename
        self.symbols_format = symbols_format
        self.xref_filename = xref_filename

        # The filename the assembler saves the assembled binary to, for
        # assemblers that support it (see commands.set_output_filename())
        self.output_filename = None

        # Was this session made using the options on the command line? (See
        # new_session().)
        self.made_from_command_line = False

        self.memory = memorymanager.Memory()
        self.moves  = movemanager.Moves()
        self.classifications = classification.Classifications()
        self.labels = labelmanager.Labels()
        self.disassembly = disassembly.DisassemblyState()     # constants, annotations, optional labels etc.
        self.trace = trace.TraceState()     # references, subroutines, hooks etc.

        # The CPU (an object of class Cpu), which is set by load()
        self.cpu = None

        # The snippets in use (see snippets6502.py): the built in ones, then
        # any registered by the control file or e.g. acorn.py.
        self.snippets = list(snippets6502.BUILTIN_SNIPPETS)

        # State kept by other modules, e.g. acorn.py, keyed by a name
        # starting with the module name (e.g. "acorn.vector_handler_count").
        self.extras = {}

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
    if name == "64tass":
        import tass64
        return tass64.Tass64()
    if name == "ca65":
        import ca65
        return ca65.Ca65()
    if name == "z88dk-8080":
        import z88dk_8080
        return z88dk_8080.Z88DK()
    utils.die("Unknown assembler '{0}' (expected beebasm, acme, xa, 64tass, ca65 or z88dk-8080)".format(name))


# The command line

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--beebasm", action="store_true", help="generate beebasm-style output (default)")
parser.add_argument("-a", "--acme", action="store_true", help="generate acme-style output")
parser.add_argument("-x", "--xa", action="store_true", help="generate xa-style output")
parser.add_argument("-t", "--64tass", dest="tass64", action="store_true", help="generate 64tass-style output")
parser.add_argument("-c", "--ca65", action="store_true", help="generate ca65-style output")
parser.add_argument("-8", "--z88dk-8080", action="store_true", help="generate z88dk style output for the 8080 processor")
parser.add_argument("-l", "--lower", action="store_true", help="generate lower-case output (default)")
parser.add_argument("-u", "--upper", action="store_true", help="generate upper-case output")
parser.add_argument("-o", "--output", help="output asm file")
parser.add_argument("--json", metavar="FILE", help="also output the disassembly as JSON to FILE (see docs/json-format.md)")
parser.add_argument("--symbols", metavar="FILE", help="also output a symbol file (each label and its address) to FILE")
parser.add_argument("--symbols-format", default="plain", choices=["plain", "vice", "beebasm", "mame"], help="the symbol file's format (default: plain)")
parser.add_argument("--xref", metavar="FILE", help="also output a cross-reference listing (each label and what refers to it) to FILE")

def options_from_command_line():
    """Read the command line, returning the options for a new session."""

    # (Other arguments are allowed, for the control file's own use.)
    args = parser.parse_known_args()[0]

    assembler_count = sum(1 for x in (args.beebasm, args.acme, args.xa, args.tass64, args.ca65, args.z88dk_8080) if x)
    if assembler_count > 1:
        utils.die("--beebasm, --acme, --xa, --64tass, --ca65 and --z88dk-8080 arguments are incompatible")
    if args.lower and args.upper:
        utils.die("--lower and --upper arguments are incompatible")

    if args.acme:
        assembler = "acme"
    elif args.xa:
        assembler = "xa"
    elif args.tass64:
        assembler = "64tass"
    elif args.ca65:
        assembler = "ca65"
    elif args.z88dk_8080:
        assembler = "z88dk-8080"
    else:
        assembler = "beebasm"

    return { "assembler": assembler, "lower_case": not args.upper, "asm_filename": args.output, "json_filename": args.json,
             "symbols_filename": args.symbols, "symbols_format": args.symbols_format, "xref_filename": args.xref }


# The current session

_current = None
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

    global _current
    from_command_line = (not options) and _use_command_line
    if from_command_line:
        options = options_from_command_line()
    _current = Session(**options)
    _current.made_from_command_line = from_command_line
    return _current

def set_current(s):
    """Make an existing session the current one, e.g. to work on two
    disassemblies side by side:

        a = session.new_session(assembler="acme")
        load(...)                       # (commands act on 'a')
        b = session.new_session(assembler="acme")
        load(...)                       # (commands act on 'b')
        session.set_current(a)
        go()                            # disassembles 'a'
    """

    global _current
    if not isinstance(s, Session):
        utils.die("set_current() needs a session (from new_session()), not {0!r}".format(s))
    _current = s

def use_command_line(enabled=True):
    """Choose whether new sessions use the options on the command line (e.g.
    --acme). This is on by default. A program that uses py8dis as a library,
    and has its own command line, can turn it off. This must be done before
    any other command."""

    global _use_command_line
    if not enabled and _current is not None and _current.made_from_command_line:
        utils.die("use_command_line(False) must be called before any other command (the command line has already been read)")
    _use_command_line = enabled
