"""
Move definition

A MoveDefinition describes one move (see movemanager.py): a block of bytes
that the program loads at one address (its binary address) and copies to
another (its runtime address) before running it. It converts addresses in the
block between the two.

movemanager.Moves.move_definitions is the list of them, indexed by move ID.
The first, the base move, covers the whole of memory, with each runtime
address the same as its binary address; move() adds the others.
"""

import memorymanager
from memorymanager import BinaryAddr, RuntimeAddr

class MoveDefinition:
    """A move definition represents a range of addresses in the binary file
    (the source of a move) and where it is relocated to at runtime (the destination).

    The 'length' bytes from binary address 'src_binary_addr' (a BinaryAddr)
    run at runtime address 'dest_runtime_addr' (a RuntimeAddr), in the same
    order.

    A later move can take some of the source bytes for itself (see
    movemanager.add_move()). The definition isn't changed when that
    happens, so a byte in the source range isn't necessarily in this move:
    movemanager.Moves.move_id_for_binary_addr says which move each byte is
    in.
    """
    def __init__(self, dest_runtime_addr, src_binary_addr, length):
        self.dest_runtime_addr = RuntimeAddr(dest_runtime_addr)
        self.src_binary_addr   = BinaryAddr(src_binary_addr)
        self.length = length

        # Plain integer versions, for speed
        self._dest = int(dest_runtime_addr)
        self._src  = int(src_binary_addr)

    def is_in_move_dest(self, runtime_addr, include_end_address):
        """Is the runtime address given within the move's destination? With
        'include_end_address', the address just after its end counts too
        (e.g. for a label just after the move's last byte)."""
        assert not isinstance(runtime_addr, BinaryAddr)
        if include_end_address:
            return self._dest <= runtime_addr <= (self._dest + self.length)
        return self._dest <= runtime_addr < (self._dest + self.length)

    def is_in_move_src(self, binary_addr, include_end_address):
        """Is the binary address given within the move's source? With
        'include_end_address', the address just after its end counts too."""
        assert not isinstance(binary_addr, RuntimeAddr)
        if include_end_address:
            return self._src <= binary_addr <= (self._src + self.length)
        return self._src <= binary_addr < (self._src + self.length)

    def convert_binary_to_runtime_addr(self, binary_addr):
        """The runtime address for a binary address in the move's source (or
        just after its end): the same distance into the destination. It's an
        assertion error if the address isn't in the source."""
        # Assert the address we want is within the move
        assert not isinstance(binary_addr, RuntimeAddr)
        assert self.is_in_move_src(binary_addr, include_end_address=True)

        # The binary address is translated to a runtime address
        return RuntimeAddr(self._dest + (int(binary_addr) - self._src))

    def convert_runtime_to_binary_addr(self, runtime_addr):
        """The binary address for a runtime address in the move's destination
        (or just after its end): the same distance into the source. It's an
        assertion error if the address isn't in the destination."""
        # Assert the address we want is within the move
        assert not isinstance(runtime_addr, BinaryAddr)
        assert self.is_in_move_dest(runtime_addr, include_end_address=True)

        return BinaryAddr(self._src + (int(runtime_addr) - self._dest))
