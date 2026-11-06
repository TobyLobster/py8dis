"""
Session

The session: the state of one disassembly. A Session object holds everything
py8dis knows about the program being disassembled: the loaded data, the
moves, the classification of each byte (as code or data), the labels, the
comments and constants, the state of the tracing, the CPU, the settings, the
assembler to write the output for, and where to write it. Each module keeps
its part of the state in an object of its own (e.g. labelmanager.Labels),
which the session holds (see Session).

Commands act on the current session, returned by current(), and so does the
rest of py8dis: a module reaches the state it needs through
session.current() each time, e.g. session.current().memory.binary. The first
time it's needed, a default session is made using the options on the command
line (e.g. --acme), unless use_command_line(False) has been called. reset()
(in commands.py) starts a new session, with new_session(). A program that
uses py8dis as a library can make sessions of its own with new_session(), and
switch between them with set_current() (see docs/commands.md).

Nothing should keep a reference to the session's state (e.g. its settings)
from one call to the next, since it will be out of date after a reset or
set_current(). Keeping all the state in one object, rather than in global
variables in each module, is what lets a reset start again from nothing, and
lets one program work on several disassemblies.

This module also reads the command line (see options_from_command_line()),
and makes the assembler object for the assembler chosen (make_assembler()).
"""

import argparse

import config
import utils

class Session:
    """The state of one disassembly (see the top of this file).

    The state is in these attributes, most of them objects from the module
    that deals with that part of it:

        settings         the settings (config.Settings), see config.py
        assembler        the assembler object (e.g. acme.Acme), which writes
                         the output in that assembler's syntax
        memory           the loaded data (memorymanager.Memory)
        moves            the moves (movemanager.Moves)
        classifications  what each byte is, and the expressions to write
                         in place of values (classification.Classifications)
        labels           the labels (labelmanager.Labels)
        disassembly      constants, comments, optional labels, memory
                         regions etc. (disassembly.DisassemblyState)
        trace            subroutines, hooks, references etc.
                         (trace.TraceState)
        cpu              the CPU (a cpu.Cpu), None until load() chooses it
        snippets         the snippets in use (see snippets6502.py)
        extras           the state of other modules, e.g. acorn.py

    and where go() writes its output (asm_filename etc., see __init__())."""

    def __init__(self, *, assembler="beebasm", lower_case=True, asm_filename=None, json_filename=None,
                 symbols_filename=None, symbols_format="plain", xref_filename=None):
        """Make a new session, with nothing loaded and the default settings.
        The arguments are the options the command line gives (see
        options_from_command_line()).

        'assembler' is the assembler to produce output for: its name (beebasm,
        baron, acme, xa, 64tass, ca65, merlin32, z88dk or sjasmplus, or
        z88dk-8080, the same as z88dk) or an assembler object.

        'lower_case' is True for lower case output, False for upper case.

        'asm_filename' is the file to write the disassembly to, or None to
        print it.

        'json_filename' is a file to write the disassembly to as JSON as well
        (see docs/json-format.md), or None.

        'symbols_filename' is a file to write the labels and their addresses
        to as well (a symbol file, see symbols.py), in 'symbols_format':
        'plain', 'vice', 'beebasm' or 'mame'. 'xref_filename' is a file to
        write a cross-reference listing to as well. None for neither.

        Stops with an error (utils.die()) for an unknown assembler name or
        symbol file format."""

        # (These modules are imported here rather than at the top of this
        # file, since they import this module themselves.)
        import classification
        import disassembly
        import labelmanager
        import memorymanager
        import movemanager
        import snippets6502
        import trace

        # The settings start at their defaults, except the case of the
        # output, which is a command line option
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
        # (One key is shared: "os_calls_named" is set by acorn.py,
        # commodore.py and cpm.py once they've named the OS calls, and checked
        # by config.set_upper_case_os_calls().) Being in the session, this
        # state is forgotten by reset() with everything else.
        self.extras = {}

def make_assembler(name):
    """Make a new assembler object (e.g. acme.Acme()), given the assembler's
    name as Session() takes it (e.g. "acme"; "z88dk-8080" is the same as
    "z88dk"). Stops with an error (utils.die()) for an unknown name."""

    # (The assembler modules are only imported when needed.)
    if name == "beebasm":
        import beebasm
        return beebasm.Beebasm()
    if name == "baron":
        import baron
        return baron.Baron()
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
    if name == "merlin32":
        import merlin32
        return merlin32.Merlin32()
    if name in ("z88dk", "z88dk-8080"):
        import z88dk
        return z88dk.Z88DK()
    if name == "sjasmplus":
        import sjasmplus
        return sjasmplus.Sjasmplus()
    utils.die("Unknown assembler '{0}' (expected beebasm, baron, acme, xa, 64tass, ca65, merlin32, z88dk or sjasmplus)".format(name))


# The command line: the options a control file takes when it's run (see
# "Command line options" in README.md). They're read when the default session
# is made, and again by reset(), by options_from_command_line().

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--beebasm", action="store_true", help="generate beebasm-style output (default)")
parser.add_argument("-r", "--baron", action="store_true", help="generate Baron-style output")
parser.add_argument("-a", "--acme", action="store_true", help="generate acme-style output")
parser.add_argument("-x", "--xa", action="store_true", help="generate xa-style output")
parser.add_argument("-t", "--64tass", dest="tass64", action="store_true", help="generate 64tass-style output")
parser.add_argument("-c", "--ca65", action="store_true", help="generate ca65-style output")
parser.add_argument("-m", "--merlin32", action="store_true", help="generate Merlin 32-style output")
parser.add_argument("-z", "--z88dk", action="store_true", help="generate z88dk style output (for the 8080 or Z80)")
parser.add_argument("-8", "--z88dk-8080", action="store_true", help="the same as --z88dk")
parser.add_argument("-s", "--sjasmplus", action="store_true", help="generate sjasmplus-style output (for the Z80)")
parser.add_argument("-l", "--lower", action="store_true", help="generate lower-case output (default)")
parser.add_argument("-u", "--upper", action="store_true", help="generate upper-case output")
parser.add_argument("-o", "--output", help="output asm file")
parser.add_argument("--json", metavar="FILE", help="also output the disassembly as JSON to FILE (see docs/json-format.md)")
parser.add_argument("--symbols", metavar="FILE", help="also output a symbol file (each label and its address) to FILE")
parser.add_argument("--symbols-format", default="plain", choices=["plain", "vice", "beebasm", "mame"], help="the symbol file's format (default: plain)")
parser.add_argument("--xref", metavar="FILE", help="also output a cross-reference listing (each label and what refers to it) to FILE")

def options_from_command_line():
    """Read the command line, returning the options for a new session (a
    dictionary of the keyword arguments for Session()).

    Stops with an error (utils.die()) if it asks for more than one assembler,
    or for both --lower and --upper. With no assembler option, the assembler
    is beebasm."""

    # (Other arguments are allowed, for the control file's own use.)
    args = parser.parse_known_args()[0]

    assembler_count = sum(1 for x in (args.beebasm, args.baron, args.acme, args.xa, args.tass64, args.ca65, args.merlin32, args.z88dk or args.z88dk_8080, args.sjasmplus) if x)
    if assembler_count > 1:
        utils.die("--beebasm, --baron, --acme, --xa, --64tass, --ca65, --merlin32, --z88dk and --sjasmplus arguments are incompatible")
    if args.lower and args.upper:
        utils.die("--lower and --upper arguments are incompatible")

    if args.baron:
        assembler = "baron"
    elif args.acme:
        assembler = "acme"
    elif args.xa:
        assembler = "xa"
    elif args.tass64:
        assembler = "64tass"
    elif args.ca65:
        assembler = "ca65"
    elif args.merlin32:
        assembler = "merlin32"
    elif args.z88dk or args.z88dk_8080:
        assembler = "z88dk"
    elif args.sjasmplus:
        assembler = "sjasmplus"
    else:
        assembler = "beebasm"

    return { "assembler": assembler, "lower_case": not args.upper, "asm_filename": args.output, "json_filename": args.json,
             "symbols_filename": args.symbols, "symbols_format": args.symbols_format, "xref_filename": args.xref }


# The current session

_current = None                        # The current session (see current())
_use_command_line = True               # See use_command_line()

def current():
    """The current session: the one that commands, and the rest of py8dis,
    act on. If there isn't one yet, the default session is made (see
    new_session()), with the options on the command line unless
    use_command_line(False) has been called."""
    if _current is None:
        new_session()
    return _current

def new_session(**options):
    """Start a new session (this is what reset() does), make it the current
    one, and return it.

    The options are as for Session(). If none are given, they come from the
    command line (unless use_command_line(False) has been called, when
    Session()'s defaults are used: beebasm, lower case, output printed). The
    session remembers whether it was made from the command line, for
    use_command_line()."""

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

    Stops with an error (utils.die()) if 's' isn't a Session.
    """

    global _current
    if not isinstance(s, Session):
        utils.die("set_current() needs a session (from new_session()), not {0!r}".format(s))
    _current = s

def use_command_line(enabled=True):
    """Choose whether new sessions use the options on the command line (e.g.
    --acme). This is on by default. A program that uses py8dis as a library,
    and has its own command line, can turn it off. This must be done before
    any other command: turning it off once a session has been made from the
    command line stops with an error (utils.die()), since the command line's
    options are already in use."""

    global _use_command_line
    if not enabled and _current is not None and _current.made_from_command_line:
        utils.die("use_command_line(False) must be called before any other command (the command line has already been read)")
    _use_command_line = enabled
