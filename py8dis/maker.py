"""
Expression makers

Functions for making expressions, e.g. make_lo("table") for the low byte of
the label 'table'.

Each returns an expression tree (see expression.py), which is turned into text
for the chosen assembler when it's output. The arguments can be strings, ints
or other expressions.

The operators are given by their generic names (e.g. 'AND', 'DIV', '<' for
the low byte), and each assembler says how to write them (see
expression.py), so e.g. make_lo(x) is '<x' for one assembler and 'x & $ff'
for another. commands.py makes these functions available to control files
(see "Making expressions" in docs/commands.md), and py8dis's own modules use
them too.
"""

from expression import Num, Unary, Binary, to_expr

# Unary operators
def make_op1(op, expr):
    """Make a unary operator expression for the assembler: 'op' (a generic
    name, e.g. 'NOT' or '<', or an alias such as '!') applied to 'expr'.

    Returns None if either is None, so a missing value passes straight
    through. Stops with an error (utils.die()) if the assembler can't write
    the operator."""

    if (op is None) or (expr is None):
        return None
    return Unary(op, to_expr(expr))

# Binary operators
def make_op2(expr1, op, expr2):
    """Make a binary operator expression for the assembler: 'expr1 op
    expr2', where 'op' is a generic name (e.g. '+', 'AND' or 'DIV') or an
    alias (e.g. '&' or '/', see expression.BINARY_ALIASES).

    Returns None if any of them is None. Stops with an error (utils.die())
    if the assembler can't write the operator."""
    if (expr1 is None) or (op is None) or (expr2 is None):
        return None
    return Binary(to_expr(expr1), op, to_expr(expr2))

def make_hex(value):
    """A number, shown in hex in the assembler's syntax (2 or 4 digits as
    needed), e.g. for a mask in make_and(x, make_hex(0xff))."""
    return Num(value, "hex")

# Convenience functions
def make_lo(expr):
    """The low byte of expr."""
    return make_op1('<', expr)

def make_hi(expr):
    """The high byte of expr."""
    return make_op1('>', expr)

def make_or(expr1, expr2):
    """expr1 OR expr2 (bitwise)."""
    return make_op2(expr1, 'OR', expr2)

def make_and(expr1, expr2):
    """expr1 AND expr2 (bitwise)."""
    return make_op2(expr1, 'AND', expr2)

def make_eor(expr1, expr2):
    """expr1 exclusive OR expr2 (bitwise)."""
    return make_op2(expr1, 'EOR', expr2)

def make_xor(expr1, expr2):
    """The same as make_eor()."""
    return make_op2(expr1, 'EOR', expr2)

def make_add(expr1, expr2):
    """expr1 + expr2. If either is the number 0, this is just the other one
    (as given, so not necessarily an expression tree), to avoid writing
    '+ 0'."""
    if isinstance(expr2, int):
        if expr2 == 0:
            return expr1
    if isinstance(expr1, int):
        if expr1 == 0:
            return expr2
    return make_op2(expr1, '+', expr2)

def make_subtract(expr1, expr2):
    """expr1 - expr2, or just expr1 (as given) if expr2 is the number 0."""
    if isinstance(expr2, int):
        if expr2 == 0:
            return expr1
    return make_op2(expr1, '-', expr2)

def make_multiply(expr1, expr2):
    """expr1 * expr2."""
    return make_op2(expr1, '*', expr2)

def make_divide(expr1, expr2):
    """expr1 divided by expr2 (the assembler's whole number division)."""
    return make_op2(expr1, 'DIV', expr2)

def make_modulo(expr1, expr2):
    """The remainder when expr1 is divided by expr2."""
    return make_op2(expr1, 'MOD', expr2)
