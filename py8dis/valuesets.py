"""
Value sets: the values an 8-bit register could have

The CPU state (see cpu6502.py) knows each register as the set of values it
could have. E.g. after 'and #$0f' A is 0 to 15, whatever it was; after 'cmp
#$cf : bcc skip' A is $cf to $ff, and after an 'asl' as well it's one of the
even values $9e to $fe (with the carry set); after 'ldx #16 : loop: ... dex :
bpl loop' X is 0 to 16 at the loop; and after 'lda flag : bmi neg : lda #0 :
... neg: lda #$80' A is 0 or $80.

A set is an int with bit v set if the value v is possible: so 1 << 5 (see
exact()) is the value 5, and FULL (all 256 bits) is a value nothing is known
about. A set is never empty: an operation on a set that isn't empty gives one
that isn't, and a branch that would rule out every value keeps what was known
(see CpuStateDisposition.set_inferred() in cpu6502.py).

The functions here work out the set of results of an operation from the sets
of its inputs. Each is exact: the result is exactly the values the operation
gives for the values in the set (and a flag is known when every value gives
it the same), worked out with shifts and masks of the whole set, rather than
value by value. (The tests in examples/cpu_state_tests.py check them against
working them out value by value.)

What's known bit by bit (known_bits()) and the least and greatest values
(bounds()) can be worked out from a set, e.g. for showing a register as
'0-' (its high hex digit known) or in the JSON output.
"""

FULL = (1 << 256) - 1
LOW_HALF = (1 << 128) - 1           # The values 0 to $7f (bit 7 clear)
HIGH_HALF = FULL ^ LOW_HALF         # The values $80 to $ff (bit 7 set)

# The values with bit k set, for each k
_HAS_BIT = [sum(1 << v for v in range(256) if (v >> k) & 1) for k in range(8)]

# For moving the values 0 to $7f to 0, 2, 4, ... $fe (and back): masks of
# runs of 2**j set bits, then 2**j clear ones, from the bottom
_RUNS = [sum(1 << i for i in range(256) if (i >> j) & 1 == 0) for j in range(8)]


def exact(value):
    """The set of just the value."""
    return 1 << (value & 0xff)


def from_range(lo, hi):
    """The set of the values from lo to hi (empty if hi < lo)."""
    if hi < lo:
        return 0
    return ((1 << (hi + 1)) - 1) & ~((1 << lo) - 1)


def from_known_bits(known, bits):
    """The set of the values that agree with the known bits (see
    known_bits())."""
    s = FULL
    for k in range(8):
        if (known >> k) & 1:
            s &= _HAS_BIT[k] if (bits >> k) & 1 else ~_HAS_BIT[k]
    return s & FULL


def count(s):
    """How many values are in the set."""
    return bin(s).count("1")


# The bits that are set in each byte value, for values()
_BYTE_BITS = [tuple(k for k in range(8) if (b >> k) & 1) for b in range(256)]

def values(s):
    """The values in the set, in order."""
    # (A byte of the set at a time, which is much quicker than a bit)
    result = []
    for i, byte in enumerate((s & FULL).to_bytes(32, "little")):
        if byte:
            base = i * 8
            result.extend(base + k for k in _BYTE_BITS[byte])
    return result


def value(s):
    """The value, if the set has just one, otherwise None."""
    if s & (s - 1) == 0:
        return s.bit_length() - 1
    return None


def bounds(s):
    """The least and greatest values in the set."""
    return (s & -s).bit_length() - 1, s.bit_length() - 1


def bit(s, k):
    """Bit k of the values, as True or False if they all agree, otherwise
    None."""
    if s & _HAS_BIT[k] == 0:
        return False
    if s & ~_HAS_BIT[k] & FULL == 0:
        return True
    return None


def known_bits(s):
    """What all the values agree on, bit by bit, as (known, bits): 'known'
    has a 1 for each bit they agree on, and 'bits' has those bits' values
    (and 0 for the others). E.g. (0xf0, 0) for 0 to 15."""
    known = 0
    bits = 0
    for k in range(8):
        b = bit(s, k)
        if b is not None:
            known |= 1 << k
            if b:
                bits |= 1 << k
    return known, bits


def n_flag(s):
    """The N flag for a result: its bit 7, or None if that depends on which
    value it is."""
    if s & HIGH_HALF == 0:
        return False
    if s & LOW_HALF == 0:
        return True
    return None


def z_flag(s):
    """The Z flag for a result: True if it's 0, False if it can't be 0,
    otherwise None."""
    if s == 1:
        return True
    if s & 1 == 0:
        return False
    return None


def rotate(s, n):
    """The set with n added to each value (wrapping round from $ff to 0)."""
    n &= 0xff
    if n == 0:
        return s
    return ((s << n) | (s >> (256 - n))) & FULL


def _carries(s, n, carry):
    """Whether adding n and carry (0 or 1) to every value carries out of
    bit 7 (True), none does (False), or it depends (None)."""
    threshold = 0x100 - n - carry       # (The least value that carries)
    if threshold <= 0:
        return True
    if s >> threshold == 0:
        return False
    if s & ((1 << threshold) - 1) == 0:
        return True
    return None


def _union(carry, f):
    """The set f(0) if the carry is clear, f(1) if it's set, or both if it
    isn't known (None)."""
    if carry is not None:
        return f(int(bool(carry)))
    return f(0) | f(1)


def _agree(carry, f):
    """The flag f(0) if the carry is clear, f(1) if it's set, or if it
    isn't known (None), what both agree on (None if they don't)."""
    if carry is not None:
        return f(int(bool(carry)))
    a, b = f(0), f(1)
    return a if a == b else None


def add(s, n, carry):
    """Adding n (an 8-bit number) and the carry (True, False or None if it
    isn't known) to each value, as binary arithmetic (ADC #n with D clear):
    (the set of results, the carry out, as True, False or None)."""
    return _union(carry, lambda c: rotate(s, n + c)), _agree(carry, lambda c: _carries(s, n, c))


def subtract(s, n, carry):
    """Subtracting n and the borrow (the carry clear) from each value, as
    binary arithmetic (SBC #n with D clear): (the set of results, the carry
    out). (SBC adds the complement of n.)"""
    return add(s, ~n & 0xff, carry)


def _overflows(n, carry):
    """The set of values v for which v + n + carry overflows: v and n have
    the same sign, and the result's is different. For n 0 to $7f, that's v
    0 to $7f whose sum is at least $80; for n $80 to $ff, v $80 to $ff whose
    sum (at least $100) is less than $180."""
    if n < 0x80:
        return from_range(max(0, 0x80 - n - carry), 0x7f)
    return from_range(0x80, min(0xff, 0x17f - n - carry))


def overflow(s, n, carry, subtracting=False):
    """The V flag after adding n and the carry to each value (or, if
    'subtracting', subtracting them: see subtract()): True or False if it's
    the same for every value (and carry, if that isn't known), otherwise
    None."""
    if subtracting:
        n = ~n & 0xff

    def v_flag(c):
        mask = _overflows(n, c)
        if s & mask == 0:
            return False
        if s & ~mask & FULL == 0:
            return True
        return None
    return _agree(carry, v_flag)


def and_(s, n):
    """AND n of each value."""
    for k in range(8):
        if not (n >> k) & 1:
            # (Values with bit k set lose it, joining those without)
            s = (s & ~_HAS_BIT[k]) | ((s & _HAS_BIT[k]) >> (1 << k))
    return s & FULL


def or_(s, n):
    """OR n of each value."""
    for k in range(8):
        if (n >> k) & 1:
            s = (s & _HAS_BIT[k]) | ((s & ~_HAS_BIT[k]) << (1 << k))
    return s & FULL


def eor(s, n):
    """EOR n of each value."""
    for k in range(8):
        if (n >> k) & 1:
            # (Swap the values with bit k set and those without)
            w = 1 << k
            s = ((s & _HAS_BIT[k]) >> w) | ((s & ~_HAS_BIT[k]) << w)
    return s & FULL


def _spread(t):
    """The set of 2v for each v (0 to $7f) in t."""
    for j in range(6, -1, -1):
        t = (t | (t << (1 << j))) & _RUNS[j]
    return t


def _gather(t):
    """The set of v for each even 2v in t (the opposite of _spread())."""
    t &= _RUNS[0]
    for j in range(7):
        t = (t | (t >> (1 << j))) & _RUNS[j + 1]
    return t & LOW_HALF


def asl(s):
    """ASL of each value: (the set of results, the carry out)."""
    return _spread((s | (s >> 128)) & LOW_HALF), bit(s, 7)


def lsr(s):
    """LSR of each value: (the set of results, the carry out)."""
    return _gather(s | (s >> 1)), bit(s, 0)


def rol(s, carry):
    """ROL of each value, with the carry in (True, False or None if it
    isn't known): (the set of results, the carry out)."""
    shifted, carry_out = asl(s)
    # (The bit rotated in makes an even result odd)
    return _union(carry, lambda c: shifted << c), carry_out


def ror(s, carry):
    """ROR of each value, with the carry in: (the set of results, the carry
    out)."""
    shifted, carry_out = lsr(s)
    return _union(carry, lambda c: shifted << (128 * c)), carry_out


def compare(s, n):
    """CMP, CPX or CPY #n of each value: (N, Z, C), each True or False if
    it's the same for every value, otherwise None. C is set if the value is
    at least n, Z if it's n, and N is bit 7 of the value minus n."""
    if s & ((1 << n) - 1) == 0:
        c = True
    elif s >> n == 0:
        c = False
    else:
        c = None
    if s == 1 << n:
        z = True
    elif not (s >> n) & 1:
        z = False
    else:
        z = None
    return n_flag(rotate(s, -n)), z, c


def show(s):
    """The value as two hex digits, with '-' for a digit that the values
    don't all agree on (e.g. '0-' after 'and #$0f')."""
    known, bits = known_bits(s)
    text = ""
    for shift in (4, 0):
        if (known >> shift) & 0xf == 0xf:
            text += "%x" % ((bits >> shift) & 0xf)
        else:
            text += "-"
    return text


def show_bits(s):
    """The value as eight binary digits, with '-' for a bit that the values
    don't all agree on (e.g. '0000----' after 'and #$0f')."""
    return "".join("-" if b is None else "01"[b] for b in (bit(s, k) for k in range(7, -1, -1)))


def describe(s):
    """The set as text, for debugging: e.g. '5', '0-15', '{0, $80}' or
    'any'."""
    if s == FULL:
        return "any"
    lo, hi = bounds(s)
    if lo == hi:
        return str(lo)
    if s == from_range(lo, hi):
        return "%d-%d" % (lo, hi)
    vs = values(s)
    if len(vs) <= 8:
        return "{" + ", ".join("$%02x" % v for v in vs) + "}"
    return "%d values from $%02x to $%02x" % (len(vs), lo, hi)
