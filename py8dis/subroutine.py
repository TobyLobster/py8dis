"""
Subroutine

What the subroutine() command (in commands.py, see docs/commands.md) is told
about a subroutine. subroutine() writes the header comment itself, then
keeps a Subroutine in the session's trace.subroutines_list (see
trace.add_subroutine()). Once the code is traced, the CPU calls each
subroutine's hook for the code that calls it, to comment the calls (see
find_subroutine_calls() in cpu6502.py and cpuz80.py), and jsonoutput.py
lists the subroutines.
"""

class Subroutine:
    """Data describing a subroutine.

        runtime_addr: its address
        move_id: the move it's in (for an address that more than one move
            puts code at), or None if not given
        label_name: its name, or None
        title, description: for its header comment, or None (the default
            hook comments each call with the title)
        on_entry, on_exit: a dictionary of a description for each register,
            e.g. {'a': "number to print"} (empty if not given)
        hook_function: called as hook_function(runtime_addr, state,
            subroutine) for each call to the subroutine, and for the code at
            its address, with the CPU state before the instruction; or None
            for no hook (hook=False)
    """

    def __init__(self, runtime_addr, label_name, title, description, on_entry, on_exit, hook_function, move_id):
        self.runtime_addr   = runtime_addr
        self.move_id        = move_id
        self.label_name     = label_name
        self.title          = title
        self.description    = description
        self.on_entry       = on_entry if on_entry else {}
        self.on_exit        = on_exit if on_exit else {}
        self.hook_function  = hook_function
