# Command reference

These are the commands you use in a control file, after `from commands import *`. They're grouped by what they're for:

- [Addresses](#addresses)
- [Loading the program](#loading-the-program)
- [Code](#code)
- [Labels](#labels)
- [Constants and expressions](#constants-and-expressions)
- [Data](#data)
- [Number formats](#number-formats)
- [Comments and layout](#comments-and-layout)
- [Reading memory](#reading-memory)
- [Making the disassembly](#making-the-disassembly)
- [Sessions: using py8dis as a library](#sessions-using-py8dis-as-a-library)

The settings (`config.set_...()`) are in [configuration.md](configuration.md). Commands for particular machines are in the [Acorn](machines/acorn.md), [Commodore](machines/commodore.md), [ZX Spectrum](machines/spectrum.md) and [CP/M](machines/cpm.md) pages. Snippets, effect patterns and hooks are in [snippets-and-hooks.md](snippets-and-hooks.md).

If a command doesn't do quite what you want, you can copy it and change it: the commands are ordinary Python functions in `py8dis/commands.py`. Suggestions and contributions of new commands are welcome.

## Addresses

Most commands take an address as their first argument. Usually it's simply the address in the program, but a program can copy part of itself somewhere else before running it (see [`move()`](#move)), and then two addresses matter:

- the **binary address**: where the bytes are when the file is loaded;
- the **runtime address**: where they are when the code runs.

Commands that take `runtime_addr` want the runtime address. Without any moves, the two are the same.

## Loading the program

### load

`load(binary_load_addr, filename, cpu_name="6502", md5sum=None, *, offset=0, length=None)`

Loads the file into py8dis's memory at `binary_load_addr`. Every control file starts with this (or `load_prg()`).

- `cpu_name` is `"6502"`, `"65C02"`, `"6510"` (the 6502 with its undocumented opcodes), `"8080"` or `"Z80"`. See [cpus.md](cpus.md).
- `md5sum`, if given, is checked against the file's md5sum, and py8dis stops if they differ. This catches the mistake of using the control file with a different version of the program.
- `offset` and `length` load only part of the file (e.g. to skip a header): `offset` is where in the file to start, and `length` is how many bytes to load (by default, the rest of the file). The `md5sum` is still that of the whole file.

A file whose name ends `.prg` or `.p00`, loaded from its start, gives a warning, since `load_prg()` is probably what's wanted.

### load_prg

`load_prg(filename, cpu_name="6502", md5sum=None)`

Loads a Commodore PRG file. Its first two bytes are the address to load the rest at, so no address is given; `load_prg()` returns it:

```python
start = load_prg("game.prg", "6510")
```

The disassembly starts with the same two bytes (e.g. `!word $0801` just before the program), so that it assembles to the whole PRG file, with acme, beebasm, xa, 64tass or ca65. To disassemble just the data, use `load(address, "game.prg", offset=2)` instead. A PC64 `.p00` file (a PRG file after a 26 byte header starting `C64File`) is also accepted; its disassembly assembles to the PRG file.

### move

`move(dest_runtime_addr, src_binary_addr, length)`

Says that the program copies `length` bytes from `src_binary_addr` to `dest_runtime_addr` before it uses them. For example, BBC Micro games that load at &1900 often copy some of their code or data, or even all of it, down to &0E00 before running it.

With the move, the labels in the block are at its runtime addresses, so the disassembly reads as the code runs. The output assembles the block for its runtime address (e.g. beebasm's `copyblock` or acme's `!pseudopc`), so it still assembles to the original file.

Call `move()` before any other command that uses the moved block: as a rule, straight after `load()`. It returns a move ID, which a few commands take (`label()`, `subroutine()`) for an address that's in more than one place. It can also be used with `with`: where an address could mean the original place or the moved block, the commands inside mean the moved block:

```python
with move(0x0900, 0x201e, 0x0f):
    label(0x0900, "print_and_inc_zp")
```

### include_binary_file

`include_binary_file(runtime_addr, relative_filepath)`

Writes the bytes at `runtime_addr` as an "include this file" directive (e.g. beebasm's `incbin`), rather than as data. py8dis checks that the file's contents are the same as the bytes there. The path is relative to the folder py8dis is run from (and is written into the output as it's given).

## Code

py8dis finds the code by tracing it: starting from the entry points you give, it follows every instruction, branch, jump and subroutine call it can. Everything it reaches is code; the rest is data. Usually a few entry points are enough.

### entry

`entry(runtime_addr, label=None, warn=True)`

Says there is code at `runtime_addr`, to trace from. If `label` is given, it names the address too (the same as calling `label()`). py8dis warns if there's no code loaded there; `warn=False` turns that off.

### nonentry

`nonentry(runtime_addr)`

Stops tracing at `runtime_addr`. For example, a conditional branch that's always taken at runtime has data after it, not code. Rarely needed.

### wordentry

`wordentry(runtime_addr, n=1)`

Marks `n` words (16-bit, low byte first) as addresses of code, e.g. a table of routines. The words are written with the routines' labels, and the routines are traced.

### code_ptr

`code_ptr(runtime_addr, runtime_addr_high=None, offset=0, label_name=None)`

Marks two bytes as the address of code, and traces the code. The low and high bytes needn't be next to each other: give the high byte's address as `runtime_addr_high` (by default it's the byte after `runtime_addr`), e.g. for a jump table with the low bytes in one table and the high bytes in another. `offset` is added to the value to get the code's address. `label_name` names the code. `code_ptr(addr)` is the same as `wordentry(addr)`.

### rts_code_ptr

`rts_code_ptr(runtime_addr, runtime_addr_high=None)`

The same as `code_ptr(..., offset=1)`: for a 6502 jump table whose entries are pushed onto the stack and "returned" to with RTS, which adds one.

### hook_subroutine

`hook_subroutine(runtime_addr, name, hook, warn=True)`

For a subroutine that doesn't simply return to the instruction after the call. The usual example is one that prints the string that follows the call, and returns after the string.

When tracing reaches a call to `runtime_addr`, py8dis calls `hook(runtime_addr, call_addr)`, where `call_addr` is the address of the call instruction. The hook returns the address where the code carries on, or `None` if it doesn't carry on (e.g. a routine that reports an error). It can also mark data (e.g. the string) and call `entry()` for more code.

`name` names the subroutine, as `entry(runtime_addr, name)` would. `warn=False` turns off the warning when the subroutine isn't in the loaded program (e.g. a ROM routine).

For the common case there are ready-made hooks: `stringhi_hook`, `stringhiz_hook`, `stringcr_hook`, `stringz_hook` and `stringn_hook` mark the string after a 3 byte call instruction (with `stringhi()` etc., below) and carry on after it:

```python
hook_subroutine(0x2040, "print_inline", stringz_hook)
```

A hook is given runtime addresses, so it reads memory with `get_u8_runtime()` etc.

### subroutine

`subroutine(runtime_addr, name=None, title=None, description=None, on_entry=None, on_exit=None, hook=None, move_id=None, is_entry_point=True)`

Describes a subroutine. All but the address are optional. py8dis writes a header comment before it, and comments the code that calls it:

```
; ***************************************************************************************
; Print a byte as hexadecimal
;
; Prints a two digit hex number 00-FF.
;
; On Entry:
;     A: number to print
;
; On Exit:
;     A: corrupted
; ***************************************************************************************
```

- `on_entry` and `on_exit` are dictionaries of a description for each register, e.g. `on_entry={'a': "number to print"}`. A description in brackets, e.g. `{'x': "(preserved)"}`, goes in the header but not in the comments on calls.
- `is_entry_point` (True by default) traces the subroutine as code.
- `hook` decides how calls are commented. By default, each call is commented with the title, and for the 6502, the instructions that set the registers before each call are commented with the descriptions (e.g. `; A=number to print`). (The 8080 has no default hook.) `hook=False` turns this off. A hook of your own is called as `hook(runtime_addr, state, subroutine)` for each call to the subroutine (for the Z80, a CALL, RST or JP to it) and for the code at its address, with the CPU's state before the instruction (see [cpus.md](cpus.md#what-py8dis-knows-about-the-registers)).

The dividing lines of stars can be changed with `config.set_subroutine_header()` and `config.set_subroutine_footer()`.

## Labels

When an instruction refers to an address (e.g. `lda $1234`), py8dis writes the address's label. An address with no label is given one automatically: `l1234` for data, or a name such as `loop_c2002` or `return_1` for code. You give better names with `label()`.

### label

`label(runtime_addr, name, move_id=None)`

Names the address. A label given with `label()` is always in the disassembly, even if nothing uses it.

### optional_label

`optional_label(runtime_addr, name, base_runtime_addr=None, *, definable_inline=True)`

Like `label()`, but the label is only output if something uses it. This is for names of addresses a program may or may not use, such as an operating system's: `acorn.bbc()` and `commodore.c64()` give hundreds of them, without filling the disassembly with unused labels.

- `base_runtime_addr` is for a name based on another address, e.g. `optional_label(0x0315, "irq_vector+1", 0x0314)`.
- `definable_inline=False` makes the label always defined at the top of the file (`name = value`), rather than at its place in the code.

An optional label isn't used if its name is already given to another address (e.g. by the control file), so that the name isn't defined twice. Names are compared in lower case for this, since some assemblers (e.g. 64tass) take `key` and `KEY` to be the same name.

### local_label

`local_label(runtime_addr, name, start_addr, end_addr, move_id=None)`

Names the address only where it's used in the code from `start_addr` up to (but not including) `end_addr`, e.g. a zero page location that a routine uses for its own purpose. Elsewhere, the address keeps its other name. If the name is already used for another address (by a local label or any other label; compared in lower case), it's written with `_2` added, with a warning.

### expr_label

`expr_label(runtime_addr, s)`

Writes the expression `s` wherever an instruction refers to `runtime_addr`, e.g. `expr_label(0x1ee4, "level_data+1")` makes `lda $1ee4,x` into `lda level_data+1,x`.

### memory_region

`memory_region(start_addr, end_addr, name)`

Names a region of memory, from `start_addr` up to (but not including) `end_addr`, e.g. `memory_region(0xfc00, 0xff00, "Hardware")`. The labels defined at the top of the disassembly ("Memory locations") are grouped by region, each group under a heading such as `; Hardware (&fc00-&feff)`. A label goes in the smallest region that contains it, so a region can be named inside a larger one. Naming the same range again renames it, and naming it `""` removes it.

The 6502 already has regions for zero page, the stack and its vectors, and `acorn.bbc()` etc. name the regions of their machines' memory. `config.set_memory_region_headings(False)` turns the headings off.

### io_range

`io_range(start_addr, end_addr)`

Says that memory from `start_addr` up to (but not including) `end_addr` is memory mapped I/O, where reading can have side effects (e.g. acknowledging an interrupt), so an instruction that reads it isn't commented as redundant (see [cpus.md](cpus.md#redundant-instructions)). `acorn.bbc()` etc. do this for &FC00-&FEFF, and `commodore.c64()` etc. for their machines' I/O.

### addr

`addr(label_name)`

Returns the runtime address of a label, e.g. `entry(addr("start"))`.

### get_label

`get_label(runtime_addr, binary_addr, *, binary_addr_type, move_id=None)`

Returns the label for `runtime_addr`, for use in an expression. `binary_addr` is where the label is used or defined, and `binary_addr_type` (a `BinaryAddrType`) says which. Mostly used by machine modules.

### set_label_maker_hook

`set_label_maker_hook(hook)`

Sets a function of your own for choosing labels' names. See [snippets-and-hooks.md](snippets-and-hooks.md#label-maker-hook).

## Constants and expressions

### constant

`constant(value, name, comment=None, *, align=Align.INLINE, format=Format.DEFAULT)`

Defines a constant: think of it as `name = value` written at the top of the output. `format` is how the value is written: `Format.DECIMAL`, `DECIMAL_SIGNED`, `HEX`, `BINARY`, `PICTURE_BINARY`, `CHAR`, `STRING` or `DEFAULT`. The comment, if any, goes with it, placed by `align` (see [`comment()`](#comment): `Align.INLINE` puts it at the end of the line).

A constant isn't used anywhere by itself. To use it, write it into an instruction with `expr()`:

- `label(42, "meaning_of_life")` makes `lda 42` into `lda meaning_of_life`, since 42 is used as an address.
- `constant(42, "meaning_of_life")` leaves `lda #42` as it is, until `expr()` (below) makes it `lda #meaning_of_life`.

So: use `label()` for addresses, and `constant()` for everything else.

### expr

`expr(runtime_addr, s)`

Writes the expression `s` in place of the value of the byte (or the 16-bit operand) at `runtime_addr`. Note that `runtime_addr` is the address of the value itself, not of the instruction it's part of; it can be data too.

```python
expr(0x2011, make_hi("screen_address"))     # lda #$30 becomes lda #>screen_address
```

`s` can instead be a dictionary of values and expressions: the byte there is looked up in it.

An expression is a string of labels, constants and arithmetic that the assembler works out. It's checked in two ways:

- When py8dis can work out its value itself (an expression made with the `make_...()` functions below, from labels and constants it knows), it checks it, and stops with an error if it's wrong, e.g. `expr() at &200a: 'length + 2' is &0f, but the byte there is &0e`.
- Otherwise (e.g. an expression you've written as text, or one that uses a name py8dis doesn't know), the output ends with assertions that make the assembler stop with an error if the value is wrong. (`config.set_include_assertions(False)` leaves them out.)

So a careless `expr()` gives an error, rather than output that assembles to a different program.

`force=False` keeps an expression already given for the address, rather than replacing it (machine modules use this).

### substitute_constants

`substitute_constants(instruction, reg, constants_dict, define_all_constants=None)`

Replaces the immediate value loaded into a register before an instruction with a name (a constant, or an expression). For example:

```python
substitute_constants("sta sprite_number", 'a', sprite_ids)
```

finds each `sta sprite_number`, then the `lda #` before it, and writes its value as a name from the dictionary `sprite_ids`:

```
    lda #SpriteId_Peanut
    sta sprite_number
```

`define_all_constants` is `None` to define no constants (the default), `False` to define the ones used, or `True` to define them all. (6502 only.)

### Making expressions

Assemblers write some operators differently (e.g. the low byte of an address is `<x` in one and `x & $ff` in another). These functions make an expression that's right for the assembler being used:

| Function                        | Gives                                    |
| ------------------------------- | ---------------------------------------- |
| `make_lo(x)`                    | the low byte                             |
| `make_hi(x)`                    | the high byte                            |
| `make_add(x, y)`                | x + y                                    |
| `make_subtract(x, y)`           | x - y                                    |
| `make_multiply(x, y)`           | x * y                                    |
| `make_divide(x, y)`             | x / y                                    |
| `make_modulo(x, y)`             | the remainder after dividing             |
| `make_or(x, y)`                 | bitwise OR                               |
| `make_and(x, y)`                | bitwise AND                              |
| `make_eor(x, y)`, `make_xor(x, y)` | bitwise exclusive OR                  |
| `make_op1(op, x)`               | any unary operator, e.g. `make_op1('NOT', 'input_bits')` |
| `make_op2(x, op, y)`            | any binary operator, e.g. `make_op2('address', 'DIV', 8)` |
| `make_hex(n)`                   | the number `n`, written in hex           |

The operators can be given in their usual forms (`+`, `-`, `*`, `/`, ...), with common alternatives (`AND` or `&`, `XOR` or `EOR`). They can be put together: `make_lo(make_add('level_data', 1))`. Brackets are added where the assembler needs them.

## Data

Whatever isn't traced as code is data. py8dis finds strings in it by itself (runs of at least three printable characters, see `go()`), and writes the rest as bytes. These commands say what the data is.

### byte and word

`byte(runtime_addr, n=1, cols=None)`

`word(runtime_addr, n=1, cols=None)`

Mark `n` bytes, or `n` words (16-bit, low byte first), as data. `cols` sets how many go on each line.

### Strings

Strings end in different ways, so there's a command for each. Each marks the string and returns the address after it, so that you can mark several in a row.

| Command                                          | The string ends                                                    |
| ------------------------------------------------ | ------------------------------------------------------------------ |
| `string(addr, n=None)`                           | after `n` characters, or at the first character that isn't printable |
| `stringterm(addr, terminator, exclude_terminator=False)` | with the byte `terminator` (included in the string, unless `exclude_terminator`) |
| `stringcr(addr, exclude_terminator=False)`       | with a carriage return (13)                                        |
| `stringz(addr, exclude_terminator=False)`        | with a zero                                                        |
| `stringhi(addr, include_terminator_fn=None)`     | with a character with bit 7 set (see below)                        |
| `stringhiz(addr, include_terminator_fn=None)`    | like `stringhi()`, or with a zero                                  |
| `stringn(addr)`                                  | after the number of characters in its first byte                   |

For `stringhi()`, the character with bit 7 set can be the last character of the string (e.g. "HELLO" with the O's bit 7 set, written as `"HELL", &80+'O'`) or something else that follows it. `include_terminator_fn` is a function that's given that byte and says whether it's part of the string; by default it isn't, and the string ends before it.

Each also takes `encoding=`, e.g. `stringz(addr, encoding="screen")`, for a string in another text encoding than the session's (see [text-encodings.md](text-encodings.md)).

### split_classification

`split_classification(runtime_addr)`

Splits the data at `runtime_addr` from the data before it, e.g. to start a new line part way through a string.

## Number formats

By default a number is written in decimal if it's a single digit, otherwise in hex. These change how the data in a block is written:

| Command                          | Format                                                          |
| -------------------------------- | --------------------------------------------------------------- |
| `char(addr, n=1)`                | a character in quotes, e.g. `'a'` (in the session's text encoding) |
| `binary(addr, n=1)`              | binary, e.g. `%01011011`                                        |
| `picture_binary(addr, n=1)`      | binary as a picture, e.g. `%#.##.##.` (for graphics), where the assembler has it |
| `decimal(addr, n=1)`             | decimal                                                         |
| `hexadecimal(addr, n=1)`         | hex: 2 digits for a value under $100, otherwise 4               |
| `uhex(addr, n=1)`                | hex, always 2 digits for a byte and 4 for a word                |
| `uint(addr, n=1)`                | the default: decimal for a single digit, otherwise hex (but without the character comment py8dis adds to some immediate values) |
| `uint_no_hex(addr, n=1)`         | decimal                                                         |
| `sint(addr, n=1)`                | a signed number                                                 |
| `padded_uint(addr, n=1)`         | like `uint()`, padded with spaces so that columns of data line up |
| `set_formatter(addr, n, formatter)` | your own: `formatter(value, bits)` gives the text for a value (`bits` is 8 or 16) |

## Comments and layout

### comment

`comment(runtime_addr, text, inline=False, indent=0, word_wrap=True, *, align=None)`

Adds a comment at the address. With `inline=True` it goes at the end of the line; otherwise it's a line (or lines) of its own, word wrapped unless `word_wrap=False`, and indented by `indent` levels.

`align` says where it goes:

- `Align.BEFORE_LABEL` or `Align.AFTER_LABEL`: before or after the address's label (if it has one);
- `Align.BEFORE_LINE` or `Align.AFTER_LINE`: before or after the line at the address;
- `Align.INLINE`: at the end of the line (the same as `inline=True`).

### formatted_comment

`formatted_comment(runtime_addr, text, inline=False, align=None, indent=0)`

The same as `comment()` with `word_wrap=False`, for text you've laid out yourself.

### no_automatic_comment

`no_automatic_comment(runtime_addr)`

Turns off the comments and expressions py8dis adds by itself at the address (e.g. on an OS call), so that you can write your own.

### blank, blank_once and annotate

`blank(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None)`

`blank_once(runtime_addr, *, align=Align.BEFORE_LABEL, priority=None)`

`annotate(runtime_addr, s, *, align=Align.BEFORE_LABEL, priority=None, once_only=False)`

`blank()` adds a blank line at the address. `annotate()` adds the text `s` as it is: it has to be something the assembler understands, so it's a last resort. `priority` orders several things at the same address. With `once_only` (or `blank_once()`), nothing is added if the same thing is already there.

## Reading memory

| Command                    | Returns                                              |
| -------------------------- | ---------------------------------------------------- |
| `get_u8_binary(addr)`      | the byte at a binary address                         |
| `get_u16_binary(addr)`     | the word (low byte first) at a binary address        |
| `get_u16_be_binary(addr)`  | the word (high byte first) at a binary address       |
| `get_u8_runtime(addr)`     | the byte at a runtime address                        |
| `get_u16_runtime(addr)`    | the word (low byte first) at a runtime address       |
| `get_u16_be_runtime(addr)` | the word (high byte first) at a runtime address      |

Without moves, binary and runtime addresses are the same. A hook is given runtime addresses, so it uses the `_runtime` versions.

## Making the disassembly

### go

`go(print_output=True, post_trace_steps=None, autostring_min_length=3)`

Does the disassembly: traces the code, finds the strings, chooses the labels' names and writes the output. Call it once, at the end of the control file. It prints the output (unless `print_output=False`, or `-o` was given on the command line) and returns it as a string.

`autostring_min_length` is the shortest run of printable characters taken to be a string. `post_trace_steps` is a function to call instead of the usual search for strings.

### reset

`reset()`

Forgets everything (the loaded data, moves, labels, constants, comments, entry points, subroutines, hooks and settings), ready to disassemble something else in the same Python script. The command line is read again, to choose the assembler and the case of the output.

```python
from commands import *

load(0x8000, "rom1.bin", "6502")
...
rom1_asm = go(print_output=False)

reset()
load(0x8000, "rom2.bin", "6502")
...
rom2_asm = go(print_output=False)
```

`add_reset_hook(hook)` registers a function for `reset()` to call, for a module of your own that keeps its own state.

### set_output_filename

`set_output_filename(filename)`

For assemblers that save the assembled program themselves (e.g. beebasm's `save` and acme's `!to`), the file name to save it as.

### is_assembler

`is_assembler(name)`

True if the output is for the named assembler (e.g. `is_assembler("acme")`), for a control file that does something different for one.

## Sessions: using py8dis as a library

All the commands act on the current session: the program being disassembled and everything known about it. Normally there's one, made from the command line when the first command is used. A program that uses py8dis as a library can make its own:

- `session.new_session(assembler="beebasm", lower_case=True, asm_filename=None, json_filename=None, symbols_filename=None, symbols_format="plain", xref_filename=None)` starts a new session (this is what `reset()` does) and returns it. The options are those of the command line (see the [README](../README.md#command-line-options)). With no options, they come from the command line.
- `session.set_current(s)` makes an earlier session the current one, e.g. to work on two disassemblies side by side.
- `session.use_command_line(False)` stops py8dis reading the command line, for a program with its own. It must be called before any other command.

```python
import session
from commands import *

a = session.new_session(assembler="acme")
load(...)                       # (commands act on 'a')
b = session.new_session(assembler="acme")
load(...)                       # (commands act on 'b')
session.set_current(a)
go()                            # disassembles 'a'
```
