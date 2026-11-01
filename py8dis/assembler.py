"""
Assembler base class

py8dis writes its output for one of several assemblers (see
docs/assemblers.md). Each is a class derived from Assembler, in a module of
its own: beebasm.py (Beebasm), baron.py (Baron, derived from Beebasm),
acme.py (Acme), xa.py (Xa), tass64.py (Tass64, for 64tass), ca65.py (Ca65),
z88dk.py (Z88DK, for z88dk-z80asm) and sjasmplus.py (Sjasmplus, derived from
Z88DK). session.make_assembler() makes the one named on the command line
(e.g. --acme), and config.get_assembler() returns the session's.

An assembler object doesn't make the output itself. Its methods are hooks,
which the rest of py8dis calls whenever it needs something written in the
assembler's syntax: a hex number, a label definition, a directive, an
operator, a character in a string. disassembly.emit() builds the output as
a list of line objects (see output.py), with a Directive line for each
directive hook (e.g. code_start(), at the start of each range of addresses);
the CPU modules make the instructions; expression.py writes the operators;
and mainformatter.py and output.py write the numbers, comments and data.

This class gives the hooks that have a default, which an assembler overrides
where its syntax differs. Its docstring lists the hooks that have no default,
which every assembler defines. It also collects the assertions written at
the end of the output (see assert_expr()).
"""

import utils

class Assembler:
    """The base class of the assemblers py8dis can write its output for (see
    the module docs). An instance holds what the assembler needs to keep
    while the output is made, e.g. the assertions for the end of the output
    ('pending_assertions', see below).

    The methods of this class are the hooks that have a default. These hooks
    have none, so every assembler class defines them:

    get_name()
        The assembler's name, e.g. 'beebasm' or '64tass': the "assembler" in
        the JSON output, and the name commands.is_assembler() checks (for a
        control file that does something different for one assembler).

    cpus_supported()
        The CPUs the assembler can assemble code for, as a list of the
        names load() takes ('6502', '65c02', '6510', '8080', 'z80'). load()
        stops with an error for any other.

    hex2(n), hex4(n), hex(n)
        The number n in the assembler's hex syntax: hex2() with two digits,
        for a byte (e.g. '&1f' or '$1f'); hex4() with four, for an address
        or a word (e.g. '&001f'); and hex() with two for a value up to $ff,
        otherwise four. They're used all over py8dis: for operands and data
        (see the formatters in mainformatter.py), label definitions,
        directives, comments and error messages. (acme's and z88dk's hex4()
        also give two digits for a value up to $ff: see acme.py.)

    comment_prefix()
        The text that starts a comment, e.g. ';'. py8dis puts a space after
        it.

    inline_label(name)
        The line that defines the label 'name' at the current address, e.g.
        '.loop' (beebasm) or 'loop:' (ca65). label.py calls it for each name
        of a label that's defined where it is in the output. An assembler
        that doesn't accept some names checks the name here (and in
        explicit_label()), and stops with utils.die() for one.

    explicit_label(name, value, offset=None, align_column=0)
        The line that defines 'name' as 'value' (text: e.g. a hex number from
        hex4(), or a label), plus 'offset' (a number added as e.g. '+1', or
        None for none), e.g. 'name = &70' or 'name EQU $70'. The name is
        padded to the column 'align_column', so that the values of a list of
        definitions line up. It's used for the "Memory locations" at the top
        of the output, for constants (see
        mainformatter.explicit_label_with_inline_comment()), and for a label
        inside an instruction or data, which is defined relative to a label
        just before it (e.g. 'l2001 = c2000+1').

    disassembly_start()
        The lines (a list of strings) at the very start of the output, e.g.
        a comment saying how to assemble it, or a directive selecting the
        CPU (beebasm's 'cpu 1' for the 65C02) or the text encodings. Can be
        empty. disassembly.emit() calls it once, before the constants.

    code_start(start_addr, end_addr, first, previous_end=None)
        The lines (a list of strings) that start a range of the output, at
        binary address start_addr (the range ends at end_addr), and set the
        address to assemble at, e.g. 'org &2000'. disassembly.emit() calls it
        with 'first' True for the first range, then again for each later
        range that doesn't follow on from the output before it (e.g. from a
        second load() at a higher address), with 'first' False and
        'previous_end' the binary address where the output before it ended.
        The output has to assemble to one file, so an assembler that doesn't
        fill the gap itself pads it here (e.g. ca65's '.res'). The default
        prg_header() calls it too.

    code_end()
        The lines that end a range of the output. Nothing calls this at the
        moment, and every assembler returns an empty list.

    pseudopc_start(dest, source, length, move_id)
        The lines that start a moved block (see move()): 'length' bytes that
        are at binary address 'source' (a memorymanager.BinaryAddr) in the
        output, but are assembled for runtime address 'dest' (a
        memorymanager.RuntimeAddr), so that their labels and operands have
        the addresses the code runs at. 'move_id' is the move's ID. E.g.
        acme's '!pseudopc'. disassembly.emit() calls it at the start of each
        range of a move, after the labels just before the block.

    pseudopc_end(dest, source, length, move_id)
        The lines that end the moved block that pseudopc_start() started
        (with the same arguments), so that the output after it is assembled
        at its binary address (source + length) again.

    disassembly_end()
        The lines at the end of the main disassembly (before the tables of
        label references etc): the assertions in 'pending_assertions', if
        config.get_include_assertions() (sorted, and each only once), and
        anything else the assembler needs at the end, e.g. beebasm's 'save'.
        disassembly.emit() calls it once, after the lines for the code and
        data are made, so all the assertions have been added by then.

    force_zp_label_prefix()
        A prefix for a label's name in an expression (see expr()) that makes
        an instruction using it take zero page addressing, e.g. '<' (low
        byte) for acme, or an empty string. py8dis itself doesn't call this:
        control files do (e.g. examples/python/dfs226.py).

    byte_prefix(), word_prefix(), string_prefix()
        The directive, with a space after it, that starts a line of data:
        bytes (e.g. 'equb '), words (two bytes, low byte first, e.g.
        'equw '), or an ASCII string (e.g. 'equs '). See output.DataBlock
        and output.StringData. They're in upper or lower case, as chosen
        (see utils.force_case()). byte_prefix() is also used for an
        instruction written as data bytes, and for a string written as
        bytes.

    char_literal(n)
        A character literal for the byte n in ASCII, e.g. "'a'", or None if
        it can't be written as one (e.g. it isn't printable, or it's a
        quote the assembler can't put in one), in which case it's written
        as a number. Used for a number whose format is 'char' (see
        expression.Num), and by the default encoded_char_literal().

    string_chr(n)
        How the byte n is written inside the double quotes of an ASCII
        string, e.g. 'a', or '""' for a double quote in 64tass, or None if
        it's written as a number, outside the quotes. Used by the default
        text_chr().

    binary_format(s)
        A number in binary, given its digits 's' (a string of '0's and '1's,
        e.g. '00101100'), e.g. '%00101100'.

    picture_binary(s)
        A number in 'picture' binary (see the picture_binary() command),
        which shows the bits as a picture, given the text binary_format()
        made for it, 's', e.g. '%..#.##..' for acme. It's 's' as it is if
        the assembler has no way to write one.

    supports_signed_integers()
        True if data can be written as a negative number (e.g. '-2' for the
        byte $fe), for the sint() command. If not, it's written as an
        unsigned decimal.

    include_binary_file(binary_filepath)
        The line that includes the file 'binary_filepath' (the path given to
        the include_binary_file() command) in place of the data it holds,
        e.g. 'incbin "file"'. A single line, not a list.

    sanitise_line(s)
        A line of the finished output, changed if the assembler needs it
        (e.g. xa's, which takes a backslash at the end of a line to join it
        to the next one). disassembly.emit() calls it for each line, after
        tidy_output()."""

    # 6502 assemblers vary in whether they take 'ROL A' or just 'ROL' for an
    # instruction that works on the accumulator. If 'explicit_a' is True,
    # py8dis writes the 'A' (see cpu6502.py).
    explicit_a = False

    # At the end of the output, py8dis writes assertions that each
    # expression it has used (e.g. one given with expr()) has the value it
    # should have there. The assembler checks them (where it can: e.g.
    # z88dk-z80asm's are only comments), which makes sure the output
    # assembles to exactly the original binary, even where py8dis can't work
    # out an expression's value itself (e.g. an expression string from the
    # control file).
    #
    # 'pending_assertions' is a dictionary from each expression to its
    # expected value (a number, or a string for a string's expression): see
    # assert_expr(). disassembly_end() writes them. (It's created in
    # __init__, so each assembler object has its own.)

    def __init__(self):
        self.pending_assertions = {}

    # Expressions (see expression.py)

    def binary_operators(self):
        """A dictionary translating generic binary operator names (e.g. 'AND',
        or its alias '&') into this assembler's syntax, e.g. {'AND': '&'}.
        None means the assembler has no such operator: py8dis stops with an
        error when an expression using it is made. Names not in the
        dictionary are used as they are (e.g. '+'). expression.Binary uses
        it when an expression is made, and each time it's rendered."""
        return {}

    def binary_precedence(self):
        """A dictionary giving how tightly each generic binary operator binds
        in this assembler (a higher number binds more tightly), by its
        generic name (e.g. 'AND', not '&'), e.g. {'*': 7, '+': 6}.
        expression.py uses it to decide where brackets are needed. An
        operator not in the dictionary has an unknown precedence, so it's
        always bracketed when it's part of a larger expression."""
        return {}

    def unary_operators(self):
        """A dictionary translating generic unary operator names (e.g. 'NOT',
        or its alias '!') into this assembler's syntax: either a prefix
        (e.g. '~'), or a template where '%s' is replaced by the operand (e.g.
        'NOT(%s)', which brings its own brackets). None means the assembler
        has no such operator: py8dis stops with an error when an expression
        using it is made. Names not in the dictionary (e.g. '<' and '>', the
        low and high byte) are used as prefixes, as they are. See
        expression.Unary."""
        return {}

    def unary_precedence(self):
        """A dictionary giving how tightly each generic unary operator binds
        when it's written as a prefix, on the same scale as
        binary_precedence(): e.g. 90 for '<' and '>' (low and high byte)
        where they bind more tightly than any binary operator, or 0 where
        they apply to the whole of the rest of the expression."""
        return {}

    def unary_rewrite(self, op, operand, nested):
        """For an assembler that writes the generic unary operator 'op' (e.g.
        '<') another way, the expression to write instead (an
        expression.Expr, e.g. 'operand AND $ff' for the low byte of
        'operand'), otherwise None, in which case it's written as
        unary_operators() says. 'nested' says whether it's part of a larger
        expression (xa's '<' and '>' can only start an operand). Called each
        time the expression is rendered."""
        return None

    def expression_in_context(self, expr, text, level, context):
        """The text to write for the expression 'expr' in the given context
        (expression.py's DEFAULT, OPERAND, ASSERTION or PREPROCESSOR), given
        its usual text, 'text', and how tightly it binds, 'level' (as in
        binary_precedence(), expression.ATOM for a name or number, or None if
        it isn't known, e.g. for an expression string from the control
        file). expression.render() calls it for every expression. By default
        the text is used as it is; an assembler overrides this where a
        context needs something different, e.g. brackets round an
        expression in an assertion."""
        return text

    def wrapped_branch_operand(self, label, offset):
        """The operand of a relative branch whose target wraps round the top
        or bottom of memory (e.g. a 6502 branch back from &0002 to &fff2, or
        a Z80 JR or DJNZ), given 'label', the label at the (wrapped) target,
        and 'offset', the distance from the branch instruction's address to
        the target as if it didn't wrap (e.g. -16). The default, the label,
        is for an assembler that wraps the target as the CPU does (acme and
        xa do). Called by cpu6502.branch_operand() and cpuz80.py."""
        return label

    def can_force_absolute(self):
        """True if the assembler can be told to use absolute addressing for
        a 6502 instruction whose operand is a zero page address, which it
        would otherwise assemble with the shorter zero page addressing (see
        force_abs_instruction()). If it can't, cpu6502.py writes such an
        instruction as data bytes, with the instruction in a comment (see
        output.Instruction's AS_DATA)."""
        return True

    def force_abs_instruction(self, mnemonic, prefix, operand, suffix):
        """The text of an instruction (after one indent) that uses absolute
        addressing although its operand is a zero page address, e.g. acme's
        'lda+2 l0070,x'. 'mnemonic' and 'suffix' (the text after the
        operand, e.g. ',x') are already in upper or lower case; 'prefix' is
        the text before the operand, and 'operand' its text. Only called (by
        output.Instruction.text()) if can_force_absolute(), so the default
        raises NotImplementedError."""
        raise NotImplementedError

    def direct_operand(self, operand):
        """The text to write for a 6502 instruction's operand that isn't
        indirect but starts with a bracket, e.g. '(table+1) - 1' in 'lda
        (table+1) - 1,y', which some assemblers would take to be indirect.
        By default it's the operand as it is. Called by
        output.Instruction.text() for an operand with no prefix that starts
        with '('. (The 8080's and Z80's operands get the same treatment from
        expression_in_context(), in the OPERAND context.)"""
        return operand

    def encoded_char_literal(self, n, encoding):
        """A character literal for the byte n in the given text encoding (a
        textencoding.Encoding), e.g. "'a'", or None if there isn't one, in
        which case it's written as a number. Used for data given with char()
        (see mainformatter.char_formatter()), in the session's encoding (see
        config.set_text_encoding()). By default only ASCII has character
        literals (see char_literal())."""
        return self.char_literal(n) if encoding.name == "ascii" else None

    def text_directive(self, encoding):
        """The directive (with a space after it) for a string in the given
        encoding (a textencoding.Encoding), e.g. '.asc ' or acme's '!pet ',
        or None if the assembler has none for it, in which case the string
        is written as bytes, with its text in a comment (see
        output.StringData). By default it's string_prefix() for ASCII, and
        None for any other encoding."""
        return self.string_prefix() if encoding.name == "ascii" else None

    def text_encoding_lines(self, encoding):
        """(lines before, lines after) a string in the given encoding (one
        with a text_directive()), as two lists of lines, e.g. 64tass's
        '.enc' lines, which select the encoding just for that string. By
        default there are none."""
        return [], []

    def tidy_output(self, lines):
        """The lines of the whole output (a list of strings), tidied if the
        assembler needs it, e.g. 64tass's, to leave out '.enc' lines that
        change nothing. disassembly.emit() calls it once, on the finished
        text, before sanitise_line(). By default the lines are unchanged."""
        return lines

    def text_chr(self, n, encoding):
        """How the byte n is written inside the double quotes of a string in
        the given encoding (one with a text_directive()), or None if it's
        written as a number, outside the quotes. By default it's
        string_chr() for ASCII, and None (so every byte is a number) for any
        other encoding."""
        return self.string_chr(n) if encoding.name == "ascii" else None

    def undocumented_6502_opcodes(self):
        """The 6502's undocumented opcodes (a set of opcode numbers, see
        cpu6510.py) that the assembler can assemble from their mnemonics,
        for the '6510' CPU. Others are written as data bytes, with the
        instruction in a comment. By default there are none."""
        return frozenset()

    def undocumented_6502_mnemonic(self, mnemonic):
        """The assembler's mnemonic for one of the undocumented opcodes it
        accepts (see undocumented_6502_opcodes()), given py8dis's name for it
        (in upper case), e.g. acme's 'ASR' for 'ALR'. By default it's
        py8dis's name."""
        return mnemonic

    def undocumented_z80_accepted(self, kind):
        """True if the assembler accepts the Z80's undocumented opcodes of
        the given kind (one of cpuz80.UNDOCUMENTED_KINDS, e.g. 'sll'), as
        cpuz80.py writes them. Those it doesn't are written as data bytes,
        with the instruction in a comment. By default none are accepted."""
        return False

    def prg_header(self, load_addr):
        """The lines at the start of the output for a PRG file loaded with
        load_prg(), as a list of strings, or None if the assembler can't do
        this (then py8dis warns that the output assembles to the data
        without it). disassembly.emit() calls it, before the first
        code_start(), if the lowest load is a PRG file (see
        memorymanager.prg_header_addr()).

        The lines assemble the file's two-byte load address, 'load_addr',
        just before the data, so that the output assembles to the whole PRG
        file: by default, code_start() at load_addr - 2, then the address as
        a word. (The code_start() that follows sets the address to
        load_addr.)"""
        # (Without code_start()'s blank lines)
        org = [line for line in self.code_start(load_addr - 2, load_addr, True) if line.strip()]
        return ["", self.comment_prefix() + " The PRG file's header: the address to load it at"] + org + [utils.make_indent(1) + self.word_prefix() + self.hex4(load_addr)]

    def hex4_for_comment(self, n):
        """A four digit hex number, for use in a comment (e.g. the memory
        region headings, such as 'Zero page ($0000-$00ff)'), where it's only
        read, not assembled. By default it's hex4()."""
        return self.hex4(n)

    def signed_hex(self, n):
        """A hex number that can be negative, e.g. '-$36' (rather than
        '$-36', which a Z80 assembler takes to be the current address minus
        $36). Used for the values in assertions."""
        return "-" + self.hex(-n) if n < 0 else self.hex(n)

    def assertion_value(self, value):
        """An assertion's expected value as text: a number (see
        signed_hex()), or a string (the value of a string's expression) in
        double quotes."""
        return self.signed_hex(value) if type(value) == int else '"' + value + '"'

    def uses_current_address(self, text):
        """True if the expression's text uses the assembler's symbol for the
        current address (e.g. '$' in 'label - $'). Its value depends on where
        it's used, so assert_expr() doesn't make an assertion for it at the
        end of the file. By default it's False."""
        return False

    def assert_expr(self, expr, value):
        """Add an assertion, for the end of the output, that the expression
        'expr' has the value 'value' (a number, or a string), unless it uses
        the current address (see uses_current_address()). Called by
        classification.check_expr() for each expression at an address, as
        it's output. See 'pending_assertions' and disassembly_end()."""
        if self.uses_current_address(str(expr)):
            return
        self.pending_assertions[expr] = value
