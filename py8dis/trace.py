"""
Trace

Follows ('traces') instructions from known entry points in order to discover
which bytes of the binary are actually code and which are data. The 'cpu'
object does the work (see cpu.py and derived classes): it is the session's
'cpu' (see session.py). This module holds the rest of the information about
the tracing process, in a TraceState held by the session.
"""

import subroutine
import session

class TraceState:
    """The state of the tracing process for one session (see session.py)."""

    def __init__(self):
        self.subroutine_argument_finder_hooks = []      # Python routines ('hooks') for naming constant arguments to subroutines
        self.substitute_constant_list         = []      # List of SubConst() objects (see cpu6502) for naming constants
        self.subroutines_list                 = []      # List of Subroutine() objects
        self.no_auto_comment_set              = set()   # binary locations not to be auto-commented
        self.references                       = None    # dictionary of references keyed by binary location
        self.analysis_hooks                   = []      # functions to call once the code is traced and its CPU states known (after the CPU's own analysis)

def add_subroutine(runtime_addr, name, title, description, entry, exit, hook_function, move_id):
    session.current().trace.subroutines_list.append(subroutine.Subroutine(runtime_addr, name, title, description, entry, exit, hook_function, move_id))

def __getattr__(name):
    """For compatibility with control files written before the session
    existed: 'trace.cpu', 'trace.references' etc. read the current session's
    values. (Code in py8dis itself uses the session directly.)"""
    if name == "cpu":
        return session.current().cpu
    if name in ("subroutine_argument_finder_hooks", "substitute_constant_list", "subroutines_list", "no_auto_comment_set", "references"):
        return getattr(session.current().trace, name)
    raise AttributeError("module 'trace' has no attribute '{0}'".format(name))
