"""
Move manager.

A "move" copies a block of bytes from some part of the "binary" (i.e.
the program being disassembled) to a different "runtime" address: the
program loads the bytes at their binary addresses, and copies them to
their runtime addresses before it runs them (see memorymanager.py, and
move() in docs/commands.md for how users see this). For example, BBC
Micro games that load at $1900 often copy some of their code down to
$0e00 before running it. With the move, py8dis traces the code, and
makes its labels, at the runtime addresses, and the output assembles the
block for its runtime address (e.g. with beebasm's copyblock or acme's
!pseudopc), so it still assembles to the original file.

Each move has a move ID: its index in Moves.move_definitions, a list of
MoveDefinition objects (see movedefinition.py). Move 0, BASE_MOVE_ID, is
the base move: it covers the whole of memory, with each runtime address
the same as its binary address, and holds every byte that isn't moved.
The move() command (in commands.py) checks its arguments and calls
add_move(), which adds a move and returns its ID, a MoveId.

A binary address can only be the source of a single move: every byte is
in exactly one move (Moves.move_id_for_binary_addr), so b2r() always has
one answer. This is a fairly natural restriction, because we're trying to
generate assembler input which will recreate the binary, and we can only
have a single classification (an instruction or data-emitting directive of
some kind) for each byte in the binary. (We don't enforce this single
source rule; instead we allow add_move() to "steal" sources from
previously defined moves.)

A runtime address, though, can be the target of more than one move. This
handles, for example, a ROM which copies different fragments of code into
a single part of RAM at different times, or the banks of a cartridge or
several sideways ROMs, which all run at $8000. Then r2b() has to choose
between them. It uses the 'active' moves: a stack of move IDs, each made
active with a 'with' block (see MoveId), e.g. 'with move(...):' in a
control file, or the move of the instruction being traced (see
cpu.Cpu.disassemble_instruction()). If none of them is active there's no
single answer.

Elsewhere, a binary address and a move ID together make a
memorymanager.BinaryLocation, and labels keep their names for each move ID
(see label.py), so that e.g. each bank can have its own names for the same
runtime address.
"""

import collections

import config
import utils
import memorymanager
import session
from movedefinition import MoveDefinition
from memorymanager import BinaryLocation, RuntimeAddr, BinaryAddr

BASE_MOVE_ID    = 0     # The base move's ID (for the bytes that aren't moved)

def is_valid_move_id(move_id):
    """True if move_id is the ID of a move: the base move, or one made by
    add_move(). (The base move's ID is valid without looking at the
    session, since Moves() makes a MoveId for it while the session is still
    being made.)"""

    return move_id == BASE_MOVE_ID or 0 <= move_id < len(session.current().moves.move_definitions)

class MoveId(int):
    """Class for a move id, that via scope manages a list of active
    move ids.

    It's an int (the move's index in Moves.move_definitions), and also a
    context manager: 'with move_id:' makes the move active for the code
    inside, by pushing it onto Moves.active_move_ids. While it's active,
    r2b() takes a runtime address that several moves put bytes at to mean
    this move's. The move() command returns one, so a control file can say
    'with move(...):', and the tracer makes each instruction's move active
    while it traces it. 'with' blocks can be nested: the innermost move
    that has the address wins.

    Making one with an ID that isn't valid (see is_valid_move_id()) is an
    assertion error."""

    def __new__(cls, value, *args, **kwargs):
        assert is_valid_move_id(value)
        return super().__new__(cls, value)

    # We define the '__enter__' and '__exit__' methods for the 'with' command
    def __enter__(self):
        """Make the move active (as the innermost active move)."""
        session.current().moves.active_move_ids.append(self)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Make the move inactive again. (It must be the innermost active
        move.)"""
        active_move_ids = session.current().moves.active_move_ids
        assert active_move_ids[-1] == self
        active_move_ids.pop()

class Moves:
    """The moves of one session (see session.py): the move definitions, which
    move each binary address is in, which moves are active, and a cache for
    move_ids_for_runtime_addr()."""

    def __init__(self):
        # active_move_ids is a list of MoveId objects, the innermost 'with'
        # block's last. It is managed by the MoveId class itself.
        self.active_move_ids = []

        # move_definitions is a list of moves, indexed by move ID, each a
        # MoveDefinition (destination runtime address, source binary address,
        # length). It starts as a single move encompassing the entire memory
        # map, the base move. Later moves "steal" binary addresses from
        # earlier moves (see move_id_for_binary_addr below), but the earlier
        # moves' definitions aren't changed when they do.
        self.move_definitions = [MoveDefinition(RuntimeAddr(0), BinaryAddr(0), 0x10000)]

        # The move id for each binary address: an array of 65536 instances of
        # one initial MoveId object. (Making the base MoveId doesn't look at
        # the session, which is still being made.) add_move() sets the move
        # id of each byte it moves.
        self.move_id_for_binary_addr = [MoveId(BASE_MOVE_ID)] * 0x10000

        # `cache` maps each runtime address that a move (other than the base
        # move) puts a byte at to the set of the IDs of those moves (see
        # move_ids_for_runtime_addr()). It's None until it's first needed.
        self.cache = None

        # `cache_move_definitions_len` is used to check if any more move()s
        # have been made and need to be cached: it's the number of moves when
        # the cache was made. (Moves are only ever added, so this is enough.)
        self.cache_move_definitions_len = None

def add_move(dest_runtime_addr, src_binary_addr, length):
    """Register the existence of a 'move' at runtime that relocates memory
    from `src_binary_addr` to `dest_runtime_addr` for `length` bytes.

    The move is recorded, and a move_id is allocated and returned to
    identify the move (a new MoveId). Each source byte is marked as being in
    the new move, taking it from whichever move had it before (usually the
    base move).

    The arguments must be a RuntimeAddr, a BinaryAddr and a length that keep
    the move in memory: bad ones are assertion errors. (The move() command
    checks the user's arguments, and that data is loaded at the source.)
    """

    assert isinstance(dest_runtime_addr, RuntimeAddr)
    assert isinstance(src_binary_addr, BinaryAddr)
    assert memorymanager.is_valid_runtime_addr(dest_runtime_addr)
    assert memorymanager.is_valid_binary_addr(src_binary_addr)
    # A move can end right at the top of memory
    assert memorymanager.is_valid_runtime_addr(dest_runtime_addr + length, allow_final_address=True)
    assert memorymanager.is_valid_binary_addr(src_binary_addr + length, allow_final_address=True)
    assert dest_runtime_addr != src_binary_addr # not fundamentally necessary, but seems sensible
    assert length > 0

    # Create a new move
    moves = session.current().moves
    move_definitions = moves.move_definitions
    move_id_for_binary_addr = moves.move_id_for_binary_addr
    move_definitions.append(MoveDefinition(dest_runtime_addr, src_binary_addr, length))

    # Create a new move id
    move_id = MoveId(len(move_definitions) - 1)

    # Mark all source memory locations with the move id
    for i in range(length):
        move_id_for_binary_addr[src_binary_addr + i] = move_id

    #utils.debug("Move {0} added. Dest = {1}, Src = {2}, Len = {3}".format(move_id, hex(dest_runtime_addr), hex(source), length))
    return move_id

def b2r(binary_addr):
    """
    Convert a binary address to a runtime address.

    Return the runtime address corresponding to a binary address;
    because a binary address can only be the source of a single move,
    there is always a single result of this mapping: the address in
    the move the byte is in (Moves.move_id_for_binary_addr).

    binary_addr must be a BinaryAddr in memory (below $10000): it's
    an assertion error otherwise.
    """

    assert isinstance(binary_addr, BinaryAddr)
    assert memorymanager.is_valid_binary_addr(binary_addr)

    # Gather information about the move
    moves = session.current().moves
    move_id = moves.move_id_for_binary_addr[binary_addr]
    if move_id == BASE_MOVE_ID:
        # (A quick path for the common case: the base move doesn't move anything)
        return RuntimeAddr(int(binary_addr))
    md = moves.move_definitions[move_id]
    return md.convert_binary_to_runtime_addr(binary_addr)

def move_ids_for_runtime_addr(runtime_addr):
    """
    Return the set of move_ids for a given runtime_address: the IDs of
    the moves that put a byte there, not counting the base move. (So
    it's empty for an address that no move() puts a byte at, and the
    address just after the end of a move isn't counted as in it.)

    Used by r2b(), and to see whether more than one move puts a byte at
    an address (e.g. banks). These results are stored in a cache for
    speed: the first time it's needed after a move is added, the answer
    for every runtime address is worked out at once, from
    Moves.move_id_for_binary_addr. The set returned is the cache's own,
    so it mustn't be changed.
    """

    assert isinstance(runtime_addr, RuntimeAddr)

    assert memorymanager.is_valid_runtime_addr(runtime_addr, True) # 0x10000 is valid for labels

    moves = session.current().moves
    # (Make the cache again if there's a move it doesn't know about yet)
    if moves.cache_move_definitions_len is None or len(moves.move_definitions) != moves.cache_move_definitions_len:
        moves.cache = collections.defaultdict(set)
        for binary_addr, move_id in enumerate(moves.move_id_for_binary_addr):
            if move_id != BASE_MOVE_ID:
                moves.cache[b2r(BinaryAddr(binary_addr))].add(move_id)
        moves.cache_move_definitions_len = len(moves.move_definitions)
    return moves.cache[runtime_addr]

def make_binloc(binary_loc):
    """binary_loc as a memorymanager.BinaryLocation. A BinaryLocation is
    returned as it is. A plain binary address (an int or BinaryAddr) is
    given the innermost active move ID (see MoveId), or if no move is
    active, the move the byte is in (Moves.move_id_for_binary_addr: the base
    move's for a byte that isn't moved, or past the top of memory).

    (While tracing, the move of the instruction being traced is active, so
    that's the move of that instruction's bytes. After tracing no move is
    active, so e.g. a comment the CPU's analysis gives a plain binary
    address in a moved block goes with that block.)"""
    if utils.is_integer_type(binary_loc):
        moves = session.current().moves
        active_move_ids = moves.active_move_ids
        if active_move_ids:
            move_id = active_move_ids[-1]
        elif 0 <= binary_loc < 0x10000:
            move_id = moves.move_id_for_binary_addr[binary_loc]
        else:
            move_id = BASE_MOVE_ID
        return BinaryLocation(BinaryAddr(binary_loc), move_id)
    assert isinstance(binary_loc, BinaryLocation)
    return binary_loc

def r2b(runtime_addr, specific_move_id=None, debug=False):
    """
    Return (binary address, move ID) corresponding to a runtime address,
    as a tuple (not a BinaryLocation), or (None, None) if there isn't one.

    If a specific_move_id is specified, use that move_id: the result is
    the binary address in that move, or (None, None) if the runtime
    address isn't in the move's destination. (The address just after
    its end counts, for a label just after the move's last byte.)

    Otherwise, because a runtime address can be the target of multiple
    moves, there may be no single correct answer:

    - If no move() puts a byte at the runtime address, it's the same
      binary address, in the base move.
    - If one move does, it's that move's byte. (A moved byte comes first:
      it's chosen even if data is also loaded at the binary address of the
      same number, which isn't moved.)
    - If several do (e.g. banks), active_move_ids is used to help
      disambiguate: it's the byte in the innermost active move of those
      (see MoveId). But if that fails, because none of them is active,
      (None, None) will be returned.

    With 'debug', the moves considered are printed.
    """

    assert isinstance(runtime_addr, RuntimeAddr)

    moves = session.current().moves
    active_move_ids = moves.active_move_ids
    if specific_move_id is None:
        # Get the set of move_ids for the runtime address
        relevant_move_ids = move_ids_for_runtime_addr(runtime_addr)
        if debug:
            utils.debug("relevant_move_ids: {0}".format(relevant_move_ids))
            utils.debug("active_move_ids: {0}".format(active_move_ids))

        # Early out if we have no relevant move ids: the address isn't moved,
        # so it's the base move's (the same binary address)
        if len(relevant_move_ids) == 0:
            return BinaryAddr(int(runtime_addr)), BASE_MOVE_ID

        specific_move_id = None
        if len(relevant_move_ids) == 1:
            # Only one relevant move id, use that (min() just takes it out of
            # the set)
            specific_move_id = min(relevant_move_ids)
        else:
            # Check for a relevant move id that is most recently active (the
            # innermost 'with' block)
            for move_id in active_move_ids[::-1]:
                if move_id in relevant_move_ids:
                    specific_move_id = move_id
                    break

        # If no relevant move is active, give up.
        if specific_move_id is None:
            return (None, None)

    # Return the binary address for the runtime address and the selected move id.
    md = moves.move_definitions[specific_move_id]
    if md.is_in_move_dest(runtime_addr, include_end_address=True):
        return (md.convert_runtime_to_binary_addr(runtime_addr), specific_move_id)
    return (None, None)

def r2b_checked(runtime_addr):
    """As r2b() but with checks for an unambiguous result, returning a
    memorymanager.BinaryLocation.

    Stops with an error (utils.die()) if the runtime address is ambiguous:
    several moves put a byte there and none of them is active. runtime_addr
    can be a plain int (but not a BinaryAddr)."""

    runtime_addr = RuntimeAddr(runtime_addr)
    assert isinstance(runtime_addr, RuntimeAddr)

    binary_addr, move_id = r2b(runtime_addr)

    if binary_addr is None:
        utils.die("Ambiguous runtime address %s" % config.get_assembler().hex(runtime_addr))

    assert move_id is not None
    return BinaryLocation(binary_addr, move_id)

def has_any_moves():
    """True if there are any moves besides the base move, i.e. move() has
    been called."""
    return len(session.current().moves.move_definitions) > 1

# Unit testing for moves (run when this file is run directly)
if __name__ == "__main__":
    def add_move_test(runtime_addr, binary_addr, length):
        return add_move(RuntimeAddr(runtime_addr), BinaryAddr(binary_addr), length)

    id1 = add_move_test(0x70, 0x1900, 10)
    id2 = add_move_test(0x70, 0x2000, 8)
    id3 = add_move_test(0x900, 0x2100, 256)

    moves = session.current().moves
    move_id_for_binary_addr = moves.move_id_for_binary_addr
    active_move_ids = moves.active_move_ids

    assert move_id_for_binary_addr[0x70] == BASE_MOVE_ID
    assert move_id_for_binary_addr[0x1900] == id1
    assert move_id_for_binary_addr[0x2000] == id2
    assert move_id_for_binary_addr[0x2000 + 8] == BASE_MOVE_ID

    assert b2r(BinaryAddr(0x70)) == 0x70
    assert b2r(BinaryAddr(0x1900)) == 0x70
    assert b2r(BinaryAddr(0x2000)) == 0x70
    assert b2r(BinaryAddr(0x2000 + 8)) == 0x2000 + 8
    assert b2r(BinaryAddr(0x2100)) == 0x900

    assert active_move_ids == []
    assert r2b(RuntimeAddr(0x70)) == (None, None)
    assert r2b(RuntimeAddr(0x900)) == (0x2100, id3)
    with id2:
        assert active_move_ids == [id2]
        assert r2b(RuntimeAddr(0x70)) == (0x2000, id2)
        assert r2b(RuntimeAddr(0x900)) == (0x2100, id3)
        assert r2b(RuntimeAddr(0x2008)) == (0x2008, BASE_MOVE_ID)
        with id1:
            assert active_move_ids == [id2, id1]
            assert r2b(RuntimeAddr(0x70)) == (0x1900, id1)
            assert r2b(RuntimeAddr(0x900)) == (0x2100, id3)
            assert r2b(RuntimeAddr(0x2008)) == (0x2008, BASE_MOVE_ID)
        assert active_move_ids == [id2]
        assert r2b(RuntimeAddr(0x70)) == (0x2000, id2)
        assert r2b(RuntimeAddr(0x900)) == (0x2100, id3)
        assert r2b(RuntimeAddr(0x2008)) == (0x2008, BASE_MOVE_ID)
    assert active_move_ids == []
    assert r2b(RuntimeAddr(0x70)) == (None, None)
    assert r2b(RuntimeAddr(0x900)) == (0x2100, id3)
