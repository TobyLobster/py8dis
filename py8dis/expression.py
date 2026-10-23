"""
Expressions

An expression (e.g. 'table+1', or the low byte of a label) is held as a small
tree of Expr objects, and only turned into text ('rendered') when it's output.
This means the tree can be rendered differently for each assembler.

The tree is made of:

    Num(value, format)          a number, shown in decimal, hex or as a character
    Name(name)                  a simple name, e.g. a constant or label name
    Raw(text)                   any other string, passed through as it is
    LazyLeaf(lazy_string)       a LazyString, e.g. a label that isn't named yet
    Unary(op, operand)          e.g. NOT, '<' (low byte) or '>' (high byte)
    Binary(left, op, right)     e.g. '+', 'AND', 'DIV'

Operator names are generic (e.g. 'AND', 'DIV', 'NOT', '<'). Each assembler
says how to write them (see the Assembler class):

    binary_operators()      how to spell each binary operator
    binary_precedence()     how tightly each binary operator binds
    unary_operators()       how to spell each unary operator
    unary_precedence()      how tightly each unary (prefix) operator binds
    unary_rewrite()         another way to write a unary operator, e.g. as a
                            binary operator for an assembler that doesn't have it

Brackets are added where they are needed: round a part of the expression
that binds less tightly than the operator it's used with. A part whose
precedence isn't known (e.g. an expression string written by the user, or an
operator the assembler doesn't say anything about) is bracketed unless it's a
simple name or number, or is already in brackets.

For clarity, brackets are also added where they aren't strictly needed, in
places where the supported assemblers disagree about precedence:

    - round a compound operand of a unary operator, e.g. '<(table + 1)'
    - round a low or high byte used in a larger expression, e.g. '(>table) + 1'
    - where a bitwise or shift operator (AND, OR, EOR, '<<', '>>') is mixed
      with a different operator, e.g. '(x + 1) AND $ff' or '(x >> 8) AND $ff'

So e.g. 'a + b + c' and 'x * 2 + 1' have no brackets.

Where an expression is used can also change how it's written, e.g. in an
assertion, or as an instruction operand. Use render(expr, context) for these.
Each assembler adjusts the text for a context (if it needs to) in its
expression_in_context() method.

Note: An expression containing a LazyString compares equal only to itself (see
Expr.__eq__()).
"""

import config
import disassembly
import utils

# The contexts an expression can be rendered for (see render())
DEFAULT      = "default"        # e.g. data, or a 6502 instruction operand
OPERAND      = "operand"        # an instruction operand (used for the 8080)
ASSERTION    = "assertion"      # an assertion that the expression has a given value
PREPROCESSOR = "preprocessor"   # a preprocessor condition (used for xa's '#if')

# Precedence levels: a higher level binds more tightly. ATOM is for something
# that never needs brackets (e.g. a name or number). None means 'not known'.
ATOM = 1000

# Generic operator names with more than one spelling
BINARY_ALIASES = { '|': 'OR', '&': 'AND', '^': 'EOR', 'XOR': 'EOR', '/': 'DIV', '%': 'MOD' }
UNARY_ALIASES  = { '!': 'NOT' }

# Operators where 'a op (b op c)' is the same as '(a op b) op c'
ASSOCIATIVE = { '+', '*', 'AND', 'OR', 'EOR' }

NO_CHAIN = frozenset()

# Arithmetic operators. All the supported assemblers agree on how these bind
# relative to each other ('*', DIV and MOD more tightly than '+' and '-'), but
# they disagree about the bitwise and shift operators. So for clarity, brackets
# are added where a bitwise or shift operator is mixed with a different
# operator, even if they aren't needed (see _operand_text()).
ARITHMETIC = { '+', '-', '*', 'DIV', 'MOD' }

# The low and high byte operators. Assemblers disagree about how tightly these
# bind, so for clarity they are bracketed when used in a larger expression.
LOW_HIGH = { '<', '>' }


class Expr:
    """Base class of all the parts of an expression tree."""

    def render(self):
        """The expression as text, for the current assembler."""
        return _render(self, nested=False)[0]

    def _render(self, nested):
        """Returns (text, level, chain): the text, how tightly it binds, and
        the set of generic operators in its 'chain' (see below). 'nested'
        says whether it's part of a larger expression.

        The chain is the operators at the top level of the text that aren't in
        brackets. e.g. for 'a - b + c' it's {'-', '+'}. An assembler works these
        out from left to right, which matters when the expression is the right
        hand operand of another operator."""
        raise NotImplementedError

    def evaluate(self, names):
        """The value of the expression, or None if it can't be worked out.
        'names' is a function giving the value of a name (or None)."""
        return None

    def is_lazy(self):
        """Does the expression contain a LazyString (e.g. a label that isn't
        named yet)? If so its text may change until all labels are named."""
        return False

    # Expressions can be used wherever a string was used before.
    def __str__(self):
        return self.render()

    def __len__(self):
        return len(self.render())

    def __format__(self, format_spec):
        return format(self.render(), format_spec)

    # Joining an expression to a string gives a string, as it did when
    # expressions were strings. (Unless the expression contains a LazyString,
    # which gives a LazyString as before.)
    def __add__(self, other):
        if not self.is_lazy() and isinstance(other, str):
            return self.render() + other
        return utils.LazyString("%s%s", self, other)

    def __radd__(self, other):
        if not self.is_lazy() and isinstance(other, str):
            return other + self.render()
        return utils.LazyString("%s%s", other, self)

    # As before, an expression containing a LazyString compares equal only to
    # itself. Other expressions compare equal to anything (including a plain
    # string) with the same text. (This matters for e.g. de-duplicating
    # assertions.)
    def __eq__(self, other):
        if self is other:
            return True
        if self.is_lazy():
            return False
        if isinstance(other, Expr):
            return (not other.is_lazy()) and self.render() == other.render()
        if isinstance(other, str):
            return self.render() == other
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        if self.is_lazy():
            return id(self)
        return hash(self.render())

    def __repr__(self):
        return "{0}({1!r})".format(type(self).__name__, self.render())


class Num(Expr):
    """A number. 'format' is how to show it:

        'decimal'
        'hex'       in the assembler's hex syntax, with 2 or 4 digits as needed
        'hex2'      in the assembler's hex syntax, with 2 digits
        'char'      as a quoted character, e.g. 'A'
    """

    def __init__(self, value, format="decimal"):
        self.value = value
        self.format = format

    def _render(self, nested):
        return (self._text(), ATOM, NO_CHAIN)

    def evaluate(self, names):
        return self.value

    def _text(self):
        if self.format == "hex":
            return config.get_assembler().hex(self.value)
        if self.format == "hex2":
            return config.get_assembler().hex2(self.value)
        if self.format == "char":
            return "'%s'" % chr(self.value)
        return str(self.value)


class Name(Expr):
    """A simple name, e.g. of a constant or label."""

    def __init__(self, name):
        self.name = name

    def _render(self, nested):
        return (self.name, ATOM, NO_CHAIN)

    def evaluate(self, names):
        return names(self.name)


class Raw(Expr):
    """Any other string, output as it is (e.g. an expression written by the user)."""

    def __init__(self, text):
        self.text = text

    def _render(self, nested):
        return (self.text, _text_level(self.text), NO_CHAIN)


class LazyLeaf(Expr):
    """A LazyString, e.g. a label name that isn't decided yet."""

    def __init__(self, lazy_string):
        self.lazy_string = lazy_string

    def _render(self, nested):
        text = str(self.lazy_string)
        return (text, _text_level(text), NO_CHAIN)

    def evaluate(self, names):
        # A label from disassembly.get_label() knows its runtime address
        runtime_addr = getattr(self.lazy_string, "runtime_addr", None)
        if runtime_addr is not None:
            return int(runtime_addr)
        return names(str(self.lazy_string))

    def is_lazy(self):
        return True


class Unary(Expr):
    """A unary operator, e.g. 'NOT', '<' (low byte) or '>' (high byte)."""

    def __init__(self, op, operand):
        self.op = op
        self.operand = operand
        self._spelling()        # (Stop now if the assembler can't handle the operator)

    def generic_op(self):
        return UNARY_ALIASES.get(self.op, self.op)

    def _spelling(self):
        trans = config.get_assembler().unary_operators()
        if self.op in trans:
            if trans[self.op] is None:
                utils.die("Assembler can't handle operator " + self.op)
            return trans[self.op]
        return self.op

    def _render(self, nested):
        assembler = config.get_assembler()
        op = self.generic_op()

        # Does the assembler write this another way? (e.g. as a binary operator)
        rewritten = assembler.unary_rewrite(op, self.operand, nested)
        if rewritten is not None:
            return _render(rewritten, nested)

        # The assembler specific operator can be a template containing '%s'
        # for where the operand goes (e.g. 'NOT(%s)'), otherwise it's a prefix.
        spelling = self._spelling()
        if "(%s)" in spelling:
            # e.g. 'NOT(%s)': it brings its own brackets
            return (spelling % _render(self.operand, nested=True)[0], ATOM, NO_CHAIN)
        if "%s" in spelling:
            # Some other template: bracket the operand unless it's simple
            return (spelling % _operand_text(self.operand, None, strict=True, unary=True)[0], None, NO_CHAIN)

        # A prefix operator
        level = assembler.unary_precedence().get(op)
        # (The chain records a low or high byte operator, see _operand_text())
        chain = frozenset({op}) if op in LOW_HIGH else NO_CHAIN
        return (spelling + _operand_text(self.operand, level, strict=True, unary=True)[0], level, chain)

    def evaluate(self, names):
        value = self.operand.evaluate(names)
        if value is None:
            return None
        op = self.generic_op()
        if op == 'NOT':
            return ~value
        if value < 0:
            return None
        if op == '<':
            return value & 0xff
        if op == '>':
            return (value >> 8) & 0xff
        return None

    def is_lazy(self):
        return self.operand.is_lazy()


class Binary(Expr):
    """A binary operator, e.g. '+', 'AND' or 'DIV'."""

    def __init__(self, left, op, right):
        self.left = left
        self.op = op
        self.right = right
        self._spelling()        # (Stop now if the assembler can't handle the operator)

    def generic_op(self):
        return BINARY_ALIASES.get(self.op, self.op)

    def _spelling(self):
        trans = config.get_assembler().binary_operators()
        if self.op in trans:
            if trans[self.op] is None:
                utils.die("Assembler can't handle operator " + self.op)
            return trans[self.op]
        return self.op

    def _render(self, nested):
        op = self.generic_op()
        level = config.get_assembler().binary_precedence().get(op)

        # Operators of the same level are worked out left to right, so the
        # left operand only needs brackets if it binds less tightly, but the
        # right operand also needs them if it binds equally tightly (unless
        # its chain is just the same associative operator, e.g. 'a + (b + c)'
        # is written 'a + b + c', but 'a | (b ^ c | d)' keeps its brackets).
        left, left_chain = _operand_text(self.left, level, strict=False, parent_op=op)
        right, right_chain = _operand_text(self.right, level, strict=True, parent_op=op, same_op_ok=op if op in ASSOCIATIVE else None)
        return (left + " " + self._spelling() + " " + right, level, frozenset({op}) | left_chain | right_chain)

    def evaluate(self, names):
        left = self.left.evaluate(names)
        right = self.right.evaluate(names)
        if left is None or right is None:
            return None
        op = self.generic_op()
        if op in _SIMPLE_OPERATORS:
            return _SIMPLE_OPERATORS[op](left, right)
        # Assemblers can differ for negative numbers here, so don't guess
        if left < 0 or right < 0:
            return None
        if op == 'DIV':
            return left // right if right != 0 else None
        if op == 'MOD':
            return left % right if right != 0 else None
        if op == '<<':
            return left << right if right < 32 else None
        if op == '>>':
            return left >> right
        return None

    def is_lazy(self):
        return self.left.is_lazy() or self.right.is_lazy()


# Operators that work the same in all assemblers, even for negative numbers
_SIMPLE_OPERATORS = {
    '+':   lambda a, b: a + b,
    '-':   lambda a, b: a - b,
    '*':   lambda a, b: a * b,
    'AND': lambda a, b: a & b,
    'OR':  lambda a, b: a | b,
    'EOR': lambda a, b: a ^ b,
}

def evaluate(value, names):
    """The value of an expression (or a string, int or LazyString), or None
    if it can't be worked out. Expression strings written by the user are
    never evaluated. 'names' is a function giving the value of a name (or None
    if it's not known)."""
    expr = to_expr(value)
    return None if expr is None else expr.evaluate(names)

def render(value, context=DEFAULT):
    """Render an expression (or a string, int or LazyString) for the current
    assembler, for use in the given context."""
    expr = to_expr(value)
    text, level, _ = _render(expr, nested=False)
    return config.get_assembler().expression_in_context(expr, text, level, context)

def in_context(value, context):
    """A LazyString that renders the expression for the given context when
    it's output."""
    return InContext(value, context)

class InContext(utils.LazyString):
    """An expression (or a string, int or LazyString) to be rendered for the
    given context (see render()) when it's output."""

    def __init__(self, value, context):
        # (As a LazyString, its text is just itself: see __str__())
        super().__init__("%s", self)
        self.value = value
        self.context = context

    def __str__(self):
        if self.resolved is None:
            self.resolved = render(self.value, self.context)
        return self.resolved

def is_fully_bracketed(text):
    """Is the whole text enclosed in one matching pair of brackets?
    e.g. '(a OR b)' is, but '(a) OR (b)' is not."""

    if not (text.startswith("(") and text.endswith(")")):
        return False
    depth = 0
    for i, c in enumerate(text):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and i != len(text) - 1:
                # The first bracket closed before the end
                return False
    return depth == 0

def to_expr(value):
    """Convert a value (an int, a string, a LazyString or an Expr) to an Expr."""

    if value is None or isinstance(value, Expr):
        return value
    if isinstance(value, utils.LazyString):
        return LazyLeaf(value)
    if utils.is_integer_type(value):
        return Num(value)
    if disassembly.is_simple_name(value):
        return Name(value)
    return Raw(value)


def _render(expr, nested):
    return to_expr(expr)._render(nested)

def _text_level(text):
    """The precedence level of some text whose structure isn't known (e.g. an
    expression string written by the user): ATOM if it never needs brackets,
    otherwise None (not known)."""

    if text.isdigit() or disassembly.is_simple_name(text) or utils.is_integer_string(text) or is_fully_bracketed(text):
        return ATOM
    return None

def _operand_text(expr, parent_level, strict, parent_op=None, same_op_ok=None, unary=False):
    """Render 'expr' as an operand of an operator of precedence level
    'parent_level', adding brackets if they are needed. Returns (text, chain),
    where chain is the part of the expression's chain (see Expr._render())
    that's at 'parent_level' and not in brackets.

    If 'strict' is True, brackets are also needed if 'expr' binds exactly as
    tightly as the operator (e.g. for the right hand operand of '-'), unless
    its chain is just the operator 'same_op_ok'.

    'parent_op' is the (generic) binary operator, or 'unary' is True for a
    unary operator. These are used to add brackets for clarity (see the
    module docstring)."""

    text, level, chain = _render(expr, nested=True)
    if level == ATOM:
        return text, NO_CHAIN
    bracketed = "(" + text + ")", NO_CHAIN

    # Needed brackets
    if level is None or parent_level is None or level < parent_level:
        return bracketed
    if level == parent_level and strict and not (same_op_ok is not None and chain == {same_op_ok}):
        return bracketed

    # Brackets for clarity
    if unary:
        return bracketed
    if parent_op is not None and (chain & LOW_HIGH):
        return bracketed
    if parent_op is not None and chain:
        involves_bitwise = not (parent_op in ARITHMETIC and chain <= ARITHMETIC)
        if involves_bitwise and chain != {parent_op}:
            return bracketed

    return (text, chain) if level == parent_level else (text, NO_CHAIN)
