import config
import disassembly
import utils

class _AtomicExpression(str):
    """A string expression that never needs brackets round it when used as
    part of a larger expression (see make_op1())."""
    pass

def bracket(expr):
    """Add brackets to an expression if it's not a simple label name or number"""

    if getattr(expr, "is_atomic", False) or isinstance(expr, _AtomicExpression):
        return expr

    if isinstance(expr, utils.LazyString):
        def late_formatter():
            strtext = str(expr)
            if strtext.isdigit() or disassembly.is_simple_name(strtext):
                return strtext
            return "({0})".format(strtext)

        return utils.LazyString("%s", late_formatter)
    elif utils.is_integer_type(expr) or expr.isdigit() or disassembly.is_simple_name(expr) or utils.is_integer_string(expr):
        return str(expr)
    return "(" + expr + ")"

# Get assembler specific operator name from a generic operator name
def assembler_op_name(s):
    """Translate an operator name into one that is assembler specific"""

    trans = config.get_assembler().translate_binary_operator_names()
    if s in trans:
        result = trans[s]
        if result is None:
            utils.die("Assembler can't handle operator " + s)
        return result
    return s

# Unary operators
def make_op1(op, expr):
    """Make a unary operator expression for the assembler"""

    if (op == None) or (expr == None):
        return None

    # In all the supported assemblers NOT binds more tightly than any binary
    # operator (or brings its own brackets), so the result never needs
    # bracketing. This is not true of '<' and '>' (e.g. in acme).
    is_atomic = op in ('NOT', '!')

    trans = config.get_assembler().translate_unary_operator_names()
    if op in trans:
        if trans[op] is None:
            utils.die("Assembler can't handle operator " + op)
        op = trans[op]

    # The assembler specific operator can be a template containing '%s' for
    # where the operand goes (e.g. 'NOT(%s)'), otherwise it's a prefix.
    template = op if "%s" in op else op + "%s"

    # No need for extra brackets if the template already provides them
    operand = expr if "(%s)" in template else bracket(expr)

    if isinstance(expr, utils.LazyString):
        result = utils.LazyString(template, operand)
        result.is_atomic = is_atomic
        return result
    result = template % operand
    return _AtomicExpression(result) if is_atomic else result

# Binary operators
def make_op2(expr1, op, expr2):
    """Make a binary operator expression for the assembler"""
    if (expr1 == None) or (op == None) or (expr2 == None):
        return None
    op_name = assembler_op_name(op)
    if op_name == None:
        return None

    if isinstance(expr1, utils.LazyString) or isinstance(expr2, utils.LazyString):
        return utils.LazyString("%s %s %s", bracket(expr1), op_name, bracket(expr2))
    return bracket(expr1) + " " + op_name + " " + bracket(expr2)

def make_hex(value):
    return config.get_assembler().hex(value)

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
