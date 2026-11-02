# Snippets and hooks

These are for going further than the ordinary commands: teaching py8dis to recognise a piece of code, or to choose names your own way. The machine modules (`acorn.py`, `commodore.py`, `spectrum.py` and `cpm.py`) are built from these, and are good examples to read.

- [Snippets](#snippets): recognising a sequence of instructions (a regex snippet)
- [Effect patterns](#effect-patterns): recognising what code does, however it's written
- [Subroutine hooks](#subroutine-hooks)
- [Label maker hook](#label-maker-hook)

## Snippets

A snippet recognises a common piece of 6502 code and comments it, or traces the code it leads to. py8dis has some built in (e.g. memory copying loops), and `acorn.bbc()`, `commodore.c64()` etc. add more (e.g. code that sets an OS vector). A control file can add its own:

`snippets6502.register_snippet(pre_trace_fn, post_trace_fn, snippet)`

py8dis calls `pre_trace_fn(p)` for each match before tracing the code (for adding entry points, with `p.entry()`), and `post_trace_fn(p)` after (for comments and expressions). Either can be None. `p` is a `SnippetHelper`, whose methods give where each named line of the snippet matched (`p.get_binary_location(name)`), the bytes there, and so on.

There are two kinds of snippet. The first, a *regex snippet*, matches a sequence of instructions:

```
loop
    lda (zp1),y
    sta (zp2),y
    dey
    bne loop
```

Each line is:

- an instruction, indented (an operand that's a name matches any value: a name starting `zp` is a zero page address, and any other name in an address is two bytes);
- `.` (any instruction);
- `!byte` or `!word` and numbers;
- alternatives separated by `|`;
- or a sequence separated by `:`.

A number is decimal, hex after `$`, `&` or `0x`, or binary after `%`, where `.` and `#` can stand for 0 and 1 (`%..##....`). An immediate value or a branch's offset can be negative (`lda #-1` is `lda #$ff`), and a number after a branch is its offset, not its target. `A` is the accumulator (`asl A`), never a name.

`?` at the start of a line makes it optional. A name at the start of a line, not indented, names that position, and can have an instruction after it (`loop lda (zp1),y`). A line py8dis can't read stops it with an error saying why. See `snippet6502.parse_snippet()`.

## Effect patterns

The second kind, an *effect pattern*, matches what the code does rather than how it does it: the values it stores to memory, and the registers at an instruction. So it matches whatever the order of the instructions, the registers used, or the other instructions between them. For example, code that sets one of two vectors to a known address:

```
lo
?   [vector = $0300 | $0302] = lo_value
hi
?   [vector+1] = hi_value
```

`[target] = value` means that code earlier in the same run of code (up to a branch target, or the end of a block such as RTS) stored the value at the target, and nothing has overwritten it, or possibly overwritten it (a JSR, or an indexed store), since.

- A **target** is an address, a variable given its addresses (`vector = $0300 | $0302`), or a variable plus or minus a number.
- A **value** is a number, a name (`lo_value`: a known value, the same wherever the name is used), or `?` (any value stored, known or not).
- `a = value` (or `x`, `y`) is a register's value.

An effect pattern can also have **instruction lines**, as a regex snippet does. Then it matches where they match (starting at an instruction in the traced code) and its effect lines hold, each effect line applying just before the instruction line after it. So the effect lines are conditions on a regex snippet's lines. For example, a call with its arguments in memory and a register, set up in any way:

```
    [$02] = bank
    a = $41
call
    jsr $ff6e
```

or two calls to OSWRCH, the first with A=22 and the second with A known, with up to two instructions between them (`lda #7`, or `ldx #7 : txa`, ...):

```
    a = 22
    jsr $ffee
?   .
?   .
mode
    a = n
    jsr $ffee
```

A match's instructions aren't matched again by the same pattern.

Without instruction lines, an effect pattern matches as soon as all its lines hold; or, if some are optional (`?`) and not all hold, when those that do stop holding, if that's enough (every line that isn't optional, and at least one line).

A match's pre-trace function is called once, while tracing (which carries on from any entry points it adds), and its post-trace function once, for the code as finally traced. In them:

- `p.matched(name)` says whether an optional line holds;
- `p.value(name)` and `p.binding(variable)` give what a value or variable matched;
- `p.store(name)` gives the store;
- `p.value_operand(name)` gives where a line's value was loaded (e.g. for `#<handler`);
- `p.extent()` gives the code from the first load to the last instruction.

The instruction lines' names work as in a regex snippet. See `effectpattern.py`.

## Subroutine hooks

Two kinds of hook can be given for a subroutine:

- `hook_subroutine(addr, name, hook)` says where the code carries on after a call, e.g. after the string that follows it (see [commands.md](commands.md#hook_subroutine));
- `subroutine(addr, ..., hook=my_hook)` comments the calls. `my_hook(runtime_addr, state, subroutine)` is called for each call to the subroutine (for the 8080 and Z80, a CALL, RST or jump to it) and for the code at its address, with the CPU's state before the instruction (see [cpus.md](cpus.md#what-py8dis-knows-about-the-registers)) and the subroutine's details (its `title`, `on_entry` and so on). The OS call comments in `acorn.py` and `commodore.py` are hooks like this.

## Label maker hook

`set_label_maker_hook(hook)`

Sets a function of your own for choosing labels' names. Given a place where a label is used, the hook can choose another name for the label. It's given a `LabelMakingData`, e.g.:

```python
def my_label_maker(d):
    # Replace one label's name with another, where it's used between two
    # binary addresses
    if d.in_range(0x0900, 0x0ab1):
        d.replace("keys", "keycounter")
        d.replace("score", "disallowedkeytab")
    elif d.in_range(0x1a26, 0x1a3a):
        d.replace("write", "string")
        d.replace("write + 1", "string + 1")
    elif d.in_range(0x2733, 0x2734):
        d.replace("birddata", "birdpixelx")
    elif d.in_range(0x277c, 0x293e):
        d.replace("read", "hiscoreaddr")
        d.replace("read + 1", "hiscoreaddr + 1")

set_label_maker_hook(my_label_maker)
```

The hook is called once for each place a label is used or defined, so for a label used in many places it's called many times. It should decide from the `LabelMakingData` it's given (the address, where the label is used, the suggested name), not from how many times it's been called or in what order. It can only be set once.
