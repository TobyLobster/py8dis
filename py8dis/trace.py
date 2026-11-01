"""
Trace

Follows ('traces') instructions from known entry points in order to discover
which bytes of the binary are actually code and which are data. The 'cpu'
object does the work (see cpu.py and derived classes): it is the session's
'cpu' (see session.py), and go() starts it with Cpu.trace(). This module holds
the rest of the information about the tracing process, in a TraceState held
by the session: what the control file and the machine modules (e.g. acorn.py)
have said about subroutines and constants, which the CPU uses while it traces
and analyses the code, and the references to each label that tracing finds.

add_subroutine() records a subroutine (see commands.subroutine()). Control
files can also read some of the state as 'trace.cpu', 'trace.references' etc.
(see __getattr__() below).
"""

import subroutine
import session

class TraceState:
    """The state of the tracing process for one session (see session.py)."""

    def __init__(self):
        self.subroutine_argument_finder_hooks = []      # Python routines ('hooks') for naming constant arguments to subroutines (6502 only, see Cpu6502.subroutine_argument_finder())
        self.substitute_constant_list         = []      # List of SubConst() objects (see cpu6502) for naming constants, from substitute_constants(), acorn.py etc.
        self.subroutines_list                 = []      # List of Subroutine() objects, from subroutine() (see add_subroutine())
        self.no_auto_comment_set              = set()   # binary addresses not to be auto-commented (see no_automatic_comment())
        self.references                       = None    # dictionary of references keyed by binary location: for each label's BinaryLocation, a list of the BinaryLocations that refer to it (made by Cpu.generate_references(), during tracing)
        self.analysis_hooks                   = []      # functions to call once the code is traced and its CPU states known (after the CPU's own analysis), e.g. from acorn.py and cpm.py

def add_subroutine(runtime_addr, name, title, description, entry, exit, hook_function, move_id):
    """Record a subroutine for the current session (see
    commands.subroutine(), which also writes its header comment). After
    tracing, the CPU calls each subroutine's hook for each call to it (see
    find_subroutine_calls() in cpu6502.py and cpuz80.py), to comment the
    calls, and jsonoutput.py lists the subroutines. 'entry' and 'exit' are
    the on_entry and on_exit dictionaries."""
    session.current().trace.subroutines_list.append(subroutine.Subroutine(runtime_addr, name, title, description, entry, exit, hook_function, move_id))

def __getattr__(name):
    """For control files that read the tracing state as module variables:
    'trace.cpu', 'trace.references' etc. read the current session's values.
    (Code in py8dis itself uses the session directly.) Any other name raises
    AttributeError, as for a missing module attribute."""
    if name == "cpu":
        return session.current().cpu
    if name in ("subroutine_argument_finder_hooks", "substitute_constant_list", "subroutines_list", "no_auto_comment_set", "references"):
        return getattr(session.current().trace, name)
    raise AttributeError("module 'trace' has no attribute '{0}'".format(name))
