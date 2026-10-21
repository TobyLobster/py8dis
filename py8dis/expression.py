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

Operator names are generic (e.g. 'AND', 'DIV', 'NOT', '<') and are translated
into the assembler's own syntax when rendered, using the assembler's
translate_binary_operator_names() and translate_unary_operator_names().

Note: This is the first stage of moving to expression trees. The trees are
rendered exactly as maker.py used to build its strings, so the output is
unchanged: anything that isn't a simple name or number is put in brackets when
it's part of a larger expression. In particular, an expression containing a
LazyString is bracketed using a slightly different rule (see _bracketed()) and
compares equal only to itself (see Expr.__eq__()), both as before.
"""

import config
import disassembly
import utils


class Expr:
    """Base class of all the parts of an expression tree."""

    # An 'atomic' expression is never bracketed when used as part of a larger
    # expression. e.g. NOT binds more tightly than any binary operator in all
    # the supported assemblers (or brings its own brackets).
    is_atomic = False

    def render(self):
        """The expression as text, for the current assembler."""
        raise NotImplementedError

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

    def render(self):
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

    def render(self):
        return self.name


class Raw(Expr):
    """Any other string, output as it is (e.g. an expression written by the user)."""

    def __init__(self, text):
        self.text = text

    def render(self):
        return self.text


class LazyLeaf(Expr):
    """A LazyString, e.g. a label name that isn't decided yet."""

    def __init__(self, lazy_string):
        self.lazy_string = lazy_string

    def render(self):
        return str(self.lazy_string)

    def is_lazy(self):
        return True


class Unary(Expr):
    """A unary operator, e.g. 'NOT', '<' (low byte) or '>' (high byte)."""

    def __init__(self, op, operand):
        self.op = op
        self.operand = operand
        self.is_atomic = op in ('NOT', '!')
        self._template()        # (Stop now if the assembler can't handle the operator)

    def _template(self):
        op = self.op
        trans = config.get_assembler().translate_unary_operator_names()
        if op in trans:
            if trans[op] is None:
                utils.die("Assembler can't handle operator " + op)
            op = trans[op]

        # The assembler specific operator can be a template containing '%s'
        # for where the operand goes (e.g. 'NOT(%s)'), otherwise it's a prefix.
        return op if "%s" in op else op + "%s"

    def render(self):
        template = self._template()
        # No need for extra brackets if the template already provides them
        operand = self.operand.render() if "(%s)" in template else _bracketed(self.operand)
        return template % operand

    def is_lazy(self):
        return self.operand.is_lazy()


class Binary(Expr):
    """A binary operator, e.g. '+', 'AND' or 'DIV'.

    'spaced' says whether there are spaces round the operator. (For now some
    expressions are written without them, e.g. 'label-1', as before.)"""

    def __init__(self, left, op, right, spaced=True):
        self.left = left
        self.op = op
        self.right = right
        self.spaced = spaced
        self._op_name()         # (Stop now if the assembler can't handle the operator)

    def _op_name(self):
        trans = config.get_assembler().translate_binary_operator_names()
        if self.op in trans:
            if trans[self.op] is None:
                utils.die("Assembler can't handle operator " + self.op)
            return trans[self.op]
        return self.op

    def render(self):
        space = " " if self.spaced else ""
        return _bracketed(self.left) + space + self._op_name() + space + _bracketed(self.right)

    def is_lazy(self):
        return self.left.is_lazy() or self.right.is_lazy()


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


def _bracketed(expr):
    """Render 'expr' for use as part of a larger expression, adding brackets
    unless it's a simple name or number."""

    if expr.is_atomic or isinstance(expr, (Num, Name)):
        return expr.render()

    text = expr.render()
    if text.isdigit() or disassembly.is_simple_name(text):
        return text

    # As before: an expression containing a LazyString doesn't check for an
    # integer string (e.g. '&ff'), but other expressions do
    if not expr.is_lazy() and utils.is_integer_string(text):
        return text
    return "(" + text + ")"
