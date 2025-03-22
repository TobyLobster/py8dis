import config
import disassembly
import utils

def bracket(expr):
    """Add brackets to an expression if it's not a simple label name or number"""

    if isinstance(expr, utils.LazyString):
        def late_formatter():
            strtext = str(expr)
            if strtext.isdigit() or disassembly.is_simple_name(strtext):
                return strtext
            return "({0})".format(strtext)

        return utils.LazyString("%s", late_formatter)
    elif utils.is_integer_type(expr) or expr.isdigit() or disassembly.is_simple_name(expr):
        return str(expr)
    return "(" + expr + ")"

# Get assembler specific operator name from a generic operator name
def assembler_op_name(s):
    """Translate an operator name into one that is assembler specific"""

    trans = config.get_assembler().translate_binary_operator_names()
    if s in trans:
        result = trans[s]
        if result == None:
            utils.error("Assembler can't handle operator " + s)
        return result
    return s

# Unary operators
def make_op1(op, expr):
    """Make a unary operator expression for the assembler"""

    if (op == None) or (expr == None):
        return None

    trans = config.get_assembler().translate_unary_operator_names()
    if op in trans:
        op = trans[op]
        if result == None:
            utils.error("Assembler can't handle operator " + op)

    if isinstance(expr, utils.LazyString):
        return utils.LazyString("%s%s", op, bracket(expr))
    return op + bracket(expr)

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
    return make_op2(expr1, '+', expr2)

def make_subtract(expr1, expr2):
    return make_op2(expr1, '-', expr2)

def make_multiply(expr1, expr2):
    return make_op2(expr1, '*', expr2)

def make_divide(expr1, expr2):
    return make_op2(expr1, 'DIV', expr2)

def make_modulo(expr1, expr2):
    return make_op2(expr1, 'MOD', expr2)
