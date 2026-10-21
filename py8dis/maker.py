"""
Functions for making expressions, e.g. make_lo("table") for the low byte of
the label 'table'.

Each returns an expression tree (see expression.py), which is turned into text
for the chosen assembler when it's output. The arguments can be strings, ints
or other expressions.
"""

from expression import Num, Unary, Binary, to_expr

# Unary operators
def make_op1(op, expr):
    """Make a unary operator expression for the assembler"""

    if (op is None) or (expr is None):
        return None
    return Unary(op, to_expr(expr))

# Binary operators
def make_op2(expr1, op, expr2):
    """Make a binary operator expression for the assembler"""
    if (expr1 is None) or (op is None) or (expr2 is None):
        return None
    return Binary(to_expr(expr1), op, to_expr(expr2))

def make_hex(value):
    """A number, shown in hex"""
    return Num(value, "hex")

# Convenience functions
def make_lo(expr):
    return make_op1('<', expr)

def make_hi(expr):
    return make_op1('>', expr)

def make_or(expr1, expr2):
    return make_op2(expr1, 'OR', expr2)

def make_and(expr1, expr2):
    return make_op2(expr1, 'AND', expr2)

def make_eor(expr1, expr2):
    return make_op2(expr1, 'EOR', expr2)

def make_xor(expr1, expr2):
    return make_op2(expr1, 'EOR', expr2)

def make_add(expr1, expr2):
    if isinstance(expr2, int):
        if expr2 == 0:
            return expr1
    if isinstance(expr1, int):
        if expr1 == 0:
            return expr2
    return make_op2(expr1, '+', expr2)

def make_subtract(expr1, expr2):
    if isinstance(expr2, int):
        if expr2 == 0:
            return expr1
    # TODO: This is wrong: 0 - x is not x. To be fixed when expressions are
    # evaluated (see claude/architecture-notes-2026-10-21.md). It's kept for
    # now so the output doesn't change.
    if isinstance(expr1, int):
        if expr1 == 0:
            return expr2
    return make_op2(expr1, '-', expr2)

def make_multiply(expr1, expr2):
    return make_op2(expr1, '*', expr2)

def make_divide(expr1, expr2):
    return make_op2(expr1, 'DIV', expr2)

def make_modulo(expr1, expr2):
    return make_op2(expr1, 'MOD', expr2)
