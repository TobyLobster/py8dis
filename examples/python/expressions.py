# Regression tests for how expressions are written (October 2026): brackets
# are only used where they are needed, or where assemblers disagree about how
# tightly operators bind (around a compound operand of '<', '>' or NOT, round
# a low or high byte used in a larger expression, and where a bitwise or shift
# operator is mixed with a different operator).
# See asm_to_create_test_binaries/expressions.asm for the expected values.

from commands import *

load(0x2000, "orig/expressions.orig", "6502", "3cae9c43d5d489f353999570645c6285")

constant(0x1234, "table")
constant(0x7f, "k")
constant(0x0f, "m")
constant(0x0f, "p")
constant(0x30, "q")
constant(0x3c, "r")
constant(1, "a")
constant(2, "b")
constant(3, "c")
constant(5, "x")
constant(10, "ten")

def test(addr, e):
    byte(addr)
    expr(addr, e)

test(0x2000, make_lo(make_add("table", 1)))                         # <(table + 1)
test(0x2001, make_add(make_hi("table"), 1))                         # (>table) + 1
test(0x2002, make_eor(make_subtract(255, "k"), 128))                # (255 - k) EOR 128
test(0x2003, make_add(make_add("a", "b"), "c"))                     # a + b + c
test(0x2004, make_add("a", make_add("b", "c")))                     # a + b + c
test(0x2005, make_subtract("ten", make_subtract("b", "c")))         # ten - (b - c)
test(0x2006, make_add(make_multiply("x", 2), 1))                    # x * 2 + 1
test(0x2007, make_multiply("x", make_add(2, 1)))                    # x * (2 + 1)
test(0x2008, make_and(make_op1("NOT", "m"), make_hex(0xff)))        # NOT(m) AND $ff
test(0x2009, make_and(make_or("p", "q"), "r"))                      # (p OR q) AND r
test(0x200a, make_or("p", make_and("q", "r")))                      # p OR (q AND r)
test(0x200b, make_and(make_lo("table"), make_hex(0x7f)))            # (<table) AND $7f
test(0x200c, make_multiply("p+1", 2))                               # (p+1) * 2
test(0x200d, make_hi(make_add("table", make_hex(0x100))))           # >(table + $100)
test(0x200e, make_eor("p", make_eor("q", "r")))                     # p EOR q EOR r
test(0x200f, make_or("p", make_eor("q", "r")))                      # p OR (q EOR r)
test(0x2010, make_and(make_op2("table", ">>", 8), make_hex(0xff)))  # (table >> 8) AND $ff
test(0x2011, make_add(make_op2(1, "<<", 3), 1))                     # (1 << 3) + 1
test(0x2012, make_divide("x", 2))                                   # x DIV 2
word(0x2013)
expr(0x2013, make_subtract("table", 1))                             # table - 1

# py8dis evaluates expressions where it can. A value that's right apart from
# being outside the range of a byte or word (e.g. from NOT, or a negative
# number) gets 'AND $ff' or 'AND $ffff' added.
test(0x2015, make_op1("NOT", "m"))                                  # NOT(m) AND $ff
test(0x2016, make_subtract(0, "k"))                                 # (0 - k) AND $ff
word(0x2017)
expr(0x2017, make_op1("NOT", "table"))                              # NOT(table) AND $ffff

go()
