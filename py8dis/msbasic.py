"""
Microsoft BASIC programs

The tokenised form of a program in Microsoft's 6502 BASIC, which the
Commodore machines' BASICs and the Apple II's Applesoft share: each line is
a link to the next line (the address after it), its line number, then its
text (keywords as tokens from $80), ending with a zero; two zero bytes end
the program. basic_lines() finds the lines, for commodore.basic_program()
and apple.applesoft_program(), which list them with their machine's
keywords.
"""

from commands import *
import memorymanager
import movemanager
from memorymanager import RuntimeAddr

def basic_lines(runtime_addr):
    """The lines of the BASIC program at the address, as a list of (address,
    link, line number, text bytes), followed by the address of the two zero
    bytes that end it; or None if there isn't a valid BASIC program there.

    Each line is a link to the next line (the address after its zero byte),
    its line number, then its text, ending with a zero. It's valid if all of
    it is loaded, each link is beyond its line's number (so the lines go up
    through memory), each line number is at most 63999, each line's only
    zero is at its end, and there are at most 1000 lines."""
    def u8(addr):
        """The byte at a runtime address, or None if it isn't loaded."""
        if addr > 0xffff:
            return None
        binary_addr, _ = movemanager.r2b(RuntimeAddr(addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            return None
        return memory_binary[binary_addr]
    def u16(addr):
        """The word (low byte first) at a runtime address, or None."""
        low, high = u8(addr), u8(addr + 1)
        return None if low is None or high is None else low + 256*high

    lines = []
    addr = runtime_addr
    while True:
        link = u16(addr)
        if link is None:
            return None
        if link == 0:
            return lines, addr
        number = u16(addr + 2)
        # The link is to the address after the line's zero byte
        if number is None or number > 63999 or link <= addr + 4 or len(lines) >= 1000:
            return None
        text = []
        for a in range(addr + 4, link - 1):
            c = u8(a)
            if c is None or c == 0:
                return None
            text.append(c)
        if u8(link - 1) != 0:
            return None
        lines.append((addr, link, number, text))
        addr = link
