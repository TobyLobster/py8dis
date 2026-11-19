"""
Known bits: what's known about each bit of an 8-bit value

The CPU state (see cpu6502.py) knows a register's value bit by bit: some
bits may be known (0 or 1) and the rest not. E.g. after 'and #$0f' the top
four bits of A are known to be 0, whatever A was; after 'ora #$80' bit 7 is
known to be 1; and after 'asl' bit 0 is known to be 0.

A value is a pair (known, bits): 'known' has a 1 for each bit that's known,
and 'bits' has those bits' values (and 0 for the bits that aren't known). So
(0xff, v) is the value v, and (0, 0) is a value nothing is known about.

The functions here work out what's known about the result of an operation
from what's known about its inputs. Each is exact where it can be cheaply:
every bit it says is known has that value for every input that agrees with
what's known about the inputs. (The tests in examples/known_bits_tests.py
check this for every input.)
"""

UNKNOWN = (0, 0)


def exact(value):
    """A value that's known (all eight bits)."""
    return (0xff, value & 0xff)


def is_exact(kb):
    """Whether all eight bits are known."""
    return kb[0] == 0xff


def bit(kb, n):
    """Bit n, as True or False, or None if it isn't known."""
    known, bits = kb
    if not (known >> n) & 1:
        return None
    return bool((bits >> n) & 1)


def with_bit(kb, n, value):
    """kb with bit n known to be value (True or False)."""
    known, bits = kb
    mask = 1 << n
    return (known | mask, (bits & ~mask) | (mask if value else 0))


def n_flag(kb):
    """The N flag for a result: its bit 7, or None if that isn't known."""
    return bit(kb, 7)


def z_flag(kb):
    """The Z flag for a result: True if it's known to be 0, False if any
    bit is known to be 1, otherwise None."""
    known, bits = kb
    if bits != 0:
        return False
    if known == 0xff:
        return True
    return None


def could_be(kb, value):
    """Whether the value could be 'value' (it agrees with the known bits)."""
    known, bits = kb
    return (value & known) == bits


def bounds(kb):
    """The least and greatest values it could be."""
    known, bits = kb
    return bits, bits | (~known & 0xff)


def and_(a, b):
    """a AND b: a bit is known if it's known in both, or known to be 0 in
    either."""
    known = (a[0] & b[0]) | (a[0] & ~a[1]) | (b[0] & ~b[1])
    return (known & 0xff, a[1] & b[1] & known & 0xff)


def or_(a, b):
    """a OR b: a bit is known if it's known in both, or known to be 1 in
    either."""
    known = (a[0] & b[0]) | a[1] | b[1]
    return (known & 0xff, (a[1] | b[1]) & 0xff)


def eor(a, b):
    """a EOR b: a bit is known if it's known in both."""
    known = a[0] & b[0]
    return (known, (a[1] ^ b[1]) & known)


def invert(a):
    """NOT a (each bit flipped)."""
    known, bits = a
    return (known, ~bits & known)


def add(a, b, carry):
    """a + b + carry, where carry is True, False (or 1, 0) or None if it
    isn't known. Returns (result, carry out): the 8-bit result's known bits,
    and the carry out, as True, False or None.

    (The 'tnum' addition used by Linux's BPF verifier: the bits that could
    differ are those where adding the unknown bits as all 0s and as all 1s
    gives different carries.)"""
    # (The carry as known bits)
    if carry is None:
        c = (0x0, 0x0)
    else:
        c = (0x1, 0x1 if carry else 0x0)

    def tnum_add(x, y):
        # (As value, mask pairs: the mask is the bits that aren't known)
        xv, xm = x
        yv, ym = y
        sm = xm + ym
        sv = xv + yv
        sigma = sm + sv
        chi = sigma ^ sv
        mu = chi | xm | ym
        return (sv & ~mu, mu)

    # Nine bits: bit 8 of the inputs is 0, and of the result is the carry
    def to_tnum(kb):
        known, bits = kb
        return (bits, ~known & 0xff)

    # (b and the carry first: with an immediate operand and a known carry
    # that sum is wholly known, so adding it to a loses nothing)
    v, m = tnum_add(to_tnum(a), tnum_add(to_tnum(b), (c[1], ~c[0] & 0x1)))
    v &= 0x1ff
    m &= 0x1ff
    result = (~m & 0xff, v & 0xff & ~m)
    carry_out = None if (m >> 8) & 1 else bool((v >> 8) & 1)
    return result, carry_out


def subtract(a, b, carry):
    """a - b - (1 - carry), as the 6502's SBC (and a compare, with carry
    True): a + NOT b + carry. Returns (result, carry out) as add() does: the
    carry out is set if there was no borrow."""
    return add(a, invert(b), carry)


def asl(a):
    """a shifted left: (result, the bit shifted out (into C))."""
    known, bits = a
    return ((known << 1 | 1) & 0xff, (bits << 1) & 0xff), bit(a, 7)


def lsr(a):
    """a shifted right: (result, the bit shifted out (into C))."""
    known, bits = a
    return ((known >> 1) | 0x80, bits >> 1), bit(a, 0)


def rol(a, carry):
    """a rotated left through carry (True, False or None):
    (result, the bit shifted out (into C))."""
    known, bits = a
    known = (known << 1) & 0xff
    bits = (bits << 1) & 0xff
    if carry is not None:
        known |= 1
        bits |= 1 if carry else 0
    return (known, bits), bit(a, 7)


def ror(a, carry):
    """a rotated right through carry (True, False or None):
    (result, the bit shifted out (into C))."""
    known, bits = a
    known >>= 1
    bits >>= 1
    if carry is not None:
        known |= 0x80
        bits |= 0x80 if carry else 0
    return (known, bits), bit(a, 0)


def show(kb):
    """The value as two hex digits, with '-' for a digit that isn't wholly
    known (e.g. '0-' after 'and #$0f')."""
    known, bits = kb
    s = ""
    for shift in (4, 0):
        if (known >> shift) & 0xf == 0xf:
            s += "%x" % ((bits >> shift) & 0xf)
        else:
            s += "-"
    return s


def show_bits(kb):
    """The value as eight binary digits, with '-' for a bit that isn't
    known (e.g. '0000----' after 'and #$0f')."""
    return "".join("-" if b is None else "01"[b] for b in (bit(kb, n) for n in range(7, -1, -1)))
