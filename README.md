# py8dis

## Table of contents
- [Overview](#overview)
- [Installation](#installation)
- [Command/function reference](#commandfunction-reference)
- [Commodore 64, VIC-20, C128 and Plus/4](#commodore-64-vic-20-c128-and-plus4)
- [JSON output](#json-output)
- [Symbol files and cross-reference listings](#symbol-files-and-cross-reference-listings)
- [Getting help](#getting-help)
- [Credits and thanks](#credits-and-thanks)

## Overview

py8dis is a programmable static tracing disassembler written in Python. It can currently disassemble 6502, 65C02 and 8080 code, and could be extended without too much difficulty to other 8-bit CPUs in the future.

## Installation

There's no real installation process as such, but you'll probably want to set PYTHONPATH to the directory containing the py8dis code. On Unix-like systems, something like this:

`export PYTHONPATH=/home/you/src/py8dis/py8dis`

will probably do the trick. On Windows (warning: I haven't tried this) you probably want something like:

`set PYTHONPATH=C:\Users\User\src\py8dis\py8dis`

If you see errors like:

`ImportError: No module named ...`

when you try to run a disassembly, PYTHONPATH probably needs adjusting. You can work around this if you just do everything in one directory, i.e. put the Python code you write to control a disassembly in the same directory as the py8dis code (commands.py, trace.py, etc).

## Demonstration / test

There is a trivial "Hello, world!" program in the `examples` subdirectory which will allow you to check py8dis is working. It also serves as a starting point you can copy when creating your own disassemblies.

If your PYTHONPATH is correct, you should be able to do:
``` sh
cd examples
python helloworld.py

```

and a disassembly of helloworld.orig will be produced:

```
; Memory locations
lffe3   = &ffe3

    org &2000

.pydis_start
    ldx #0                                                            ; 2000: a2 00       ..
; &2002 referenced 1 time by &200b
.loop_c2002
    lda l200e,x                                                       ; 2002: bd 0e 20    ..
    jsr lffe3                                                         ; 2005: 20 e3 ff     ..
    inx                                                               ; 2008: e8          .
    cpx #&0e                                                          ; 2009: e0 0e       ..
    bne loop_c2002                                                    ; 200b: d0 f5       ..
    rts                                                               ; 200d: 60          `

; &200e referenced 1 time by &2002
.l200e
    equs "Hello, world!"                                              ; 200e: 48 65 6c... Hel
    equb &0d                                                          ; 201b: 0d          .
.pydis_end


save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l200e:        1
;     lffe3:        1
;     loop_c2002:   1

; Automatically generated labels:
;     l200e
;     lffe3
;     loop_c2002

; Stats:
;     Total size (Code + Data) = 28 bytes
;     Code                     = 14 bytes (50%)
;     Data                     = 14 bytes (50%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 13 bytes
;     Number of strings        = 1
```

This output is suitable for feeding into the beebasm assembler. You can switch to produce output suitable for other assemblers:

| assembler                                                 | CPUs supported | command line                    |
| --------------------------------------------------------  | -------------- | ------------------------------- |
| [acme](https://sourceforge.net/projects/acme-crossass/)   | 6502 / 65C02   | --acme                          |
| [beebasm](https://github.com/stardot/beebasm)             | 6502 / 65C02   | --beebasm (this is the default) |
| [xa](https://www.floodgap.com/retrotech/xa/)              | 6502 / 65C02   | --xa                            |
| [z88dk-z80asm](https://z88dk.org)                         | 8080           | --z88dk-8080                    |

Other command line options: `-o FILE` writes the output to a file instead of printing it, `--upper` or `--lower` choose the case of the output, `--json FILE` writes the disassembly as JSON as well (see [JSON output](#json-output)), and `--symbols FILE` (with `--symbols-format`) and `--xref FILE` write a symbol file and a cross-reference listing (see [Symbol files and cross-reference listings](#symbol-files-and-cross-reference-listings)).

### Running the tests

The `examples` directory also has py8dis's tests: control files in `examples/python`, the binaries they disassemble in `examples/orig`, and the output they should give in `examples/known_good`. To run them all and check the output:

``` sh
cd examples
./run_tests.py -c
```

py8dis itself needs only Python 3. The tests also use these, when they're installed, and skip what needs them otherwise:

- the assemblers (acme, beebasm, xa and z88dk-z80asm), to check that each disassembly assembles to the original binary;
- the [jsonschema](https://pypi.org/project/jsonschema/) package (`pip install jsonschema`), to check the JSON output against its schema (see [JSON output](#json-output)). Without it, `run_tests.py -c` says so at the end.

`./run_tests.py --help` describes the other options, e.g. running particular tests, and `-m` to make the known good output after a deliberate change.

### Edit me

The output of the hello world example can be improved. Load helloworld.py and add:

    import acorn
    acorn.bbc()

This defines BBC Micro OS specific constants, which resolves &ffe3 into a proper label name. Add:

    label(0x2002, "print_message_loop")
    label(0x200e, "message")

to give proper names for the remaining labels.

## Configuration reference

To change the configuration, add `import config` and call the following as needed:

| Functions                                             | Default | Notes                                                            |
| ----------------------------------------------------- | :-----: | ---------------------------------------------------------------- |
| `config.set_lower_case(b)`                            | True    | Set output to be upper or lower case.                            |
| `config.set_hex_dump(b)`                              | True    | Show or hide hex dump output.                                    |
| `config.set_label_references(b)`                      | True    | Show or hide output of label references.                         |
| `config.set_inline_comment_column(n)`                 | 70      | Specify the character column where inline comments start.        |
| `config.set_word_wrap_comment_column(n)`              | 87      | Specify the character column where word wrapping occurs.         |
| `config.set_indent_string(s)`                         | " "*4   | Set the string (usually spaces) for one indent level.            |
| `config.set_indent_loops(b)`                          | False   | Set whether looping code is indented or not.                     |
| `config.set_blank_line_at_block_end(b)`               | True    | Add a blank line at the end of a block of data.                  |
| `config.set_loop_limit(i)`                            | 32      | Set the maximum number of bytes that counts as a loop.           |
| `config.set_show_cpu_state(b)`                        | False   | Show or hide the output for the CPU state.                       |
| `config.set_show_autogenerated_labels(b)`             | True    | Show or hide a list of the autogenerated labels.                 |
| `config.set_show_char_literals(b)`                    | True    | Show or hide character literals comments.                        |
| `config.set_show_all_labels(b)`                       | False   | Show or hide a list of all labels used (for debugging py8dis).   |
| `config.set_hex_dump_max_bytes(i)`                    | 3       | Set the number of hex bytes output on a single line.             |
| `config.set_show_cycles(b)`                           | False   | Show the number of cycles taken by each instruction.             |
| `config.set_subroutine_header(s)`                     | "*"*87  | A dividing line at the start of a subroutine comment.            |
| `config.set_subroutine_footer(s)`                     | "*"*87  | A dividing line at the end of a subroutine comment.              |
| `config.set_include_assertions(b)`                    | True    | Include assertions at end of output to detect misuse of expr().  |
| `config.set_label_return_instructions_numerically(b)` | True    | Gives 'return_1' style labels where the destination is RTS.      |
| `config.set_show_stats(b)`                            | True    | Show statistics at the end of the disassembly.                   |
| `config.set_memory_region_headings(b)`                | True    | Group the memory locations at the top by region, with headings.  |
| `config.set_text_encoding(s)`                         | "ascii" | How bytes are shown as text: "ascii", "petscii" or "screen" (see [Text encodings](#text-encodings)). |

## Command reference

The whole point of py8dis is that it's programmable/user-extendable, but standard Python functions are provided for common disassembly tasks. If these don't do quite what you want, you can always copy them and tweak the definitions; alternatively, feature requests or submissions of new "standard" functions to add are welcome.

In what follows a `binary_addr` refers to a location in memory where the binary file is loaded. Often memory is moved (relocated) soon after loading, before being executed. `runtime_addr` refers to a memory location after the code/data has been relocated as specified by any `move()` commands.

### Initialisation

:pencil:`load(binary_load_addr, filename, cpu_name="6502", md5sum=None, *, offset=0, length=None)`

Load the contents of `filename` into the disassembler's memory at address `binary_load_addr`. `cpu_name` can be "6502", "65C02", "6510" or "8080". If the optional `md5sum` argument is provided, disassembly will fail if the md5sum of `filename`'s contents doesn't match; this allows you to detect if a disassembly is being used against a different version of a program by accident.

"6510" is the 6502 with its undocumented opcodes (as on the Commodore 64's 6510, and any NMOS 6502): SLO, RLA, SRE, RRA, SAX, LAX, DCP, ISC, ANC, ALR, ARR, SBX, SBC (&EB), NOP with operands, JAM, and the unstable ANE, LXA, LAS, TAS, SHA, SHX and SHY. These are traced as what they do (with their cycle counts, and what's known of the registers afterwards), so code that uses them is disassembled properly. acme writes them with its own mnemonics (after `!cpu 6510`; ALR is written as ASR, which older versions of acme need), except where an instruction has several opcodes and acme uses another one (e.g. ANC &2B, or most of the NOPs); those, and all of them for beebasm and xa, are written as data bytes with the instruction in a comment, e.g. `equb &a7, l0070 ; lax l0070 (undocumented)`. With "6502" they aren't traced: tracing stops at one, since treating unknown opcodes as code would turn data into nonsense instructions.

To load only part of the file (e.g. to skip a header), give `offset`, where in the file to start, and optionally `length`, the number of bytes to load (by default, the rest of the file). The `md5sum` is still that of the whole file. A file whose name ends `.prg` or `.p00` gives a warning when loaded from its start, since `load_prg()` (below) is probably what's wanted.

:pencil:`load_prg(filename, cpu_name="6502", md5sum=None)`

Load a Commodore PRG file. Its first two bytes are the address to load the rest of it at, so no address is given; `load_prg()` returns it:

```python
start = load_prg("game.prg", "6502")
```

The disassembly starts with the same two bytes (e.g. `!word $0801` just before the program), so that it assembles to the whole PRG file, with acme, beebasm or xa. (To disassemble just the data, use `load(address, "game.prg", offset=2)` instead.) A PC64 `.p00` file, which is a PRG file after a 26 byte header starting `C64File`, is also accepted; its disassembly assembles to the PRG file.

### Labels

:pencil:`label(runtime_addr, name, move_id=None)`

Provide a label `name` for memory address `runtime_addr`. The `name` is used automatically when disassembling an instruction which references the address. If no label name is available when disassembling, one will be automatically created (of the form `l1900`).

Labels defined with `label()` are always included in the disassembly even if they're never referenced; see `optional_label` if you don't want this behaviour.

:pencil:`optional_label(runtime_addr, name, base_runtime_addr=None, *, definable_inline=True)`

This is like `label`, but the disassembly will omit the label if it isn't referenced. This is intended for use in re-usable library functions like `acorn.add_standard_labels`. If an OS entry point or special memory address is used in the code it's good to have it referred to by a recognisable name, but it's not good to bloat the disassembly with labels for perhaps hundreds of special addresses that aren't used. `definable_inline` determines if the label should be defined at the top of the file as `label = value` style, or if it can be defined in the body of the disassembly.

:pencil:`memory_region(start_addr, end_addr, name)`

Names a region of memory, from `start_addr` up to (but not including) `end_addr`, e.g. `memory_region(0xfc00, 0xff00, "Hardware")`. The labels defined as `label = value` at the top of the disassembly ("Memory locations") are grouped by region, each group under a heading such as `; Hardware (&fc00-&feff)`. A label goes in the smallest region that contains it, so a region can be named inside a larger one. Naming the same range again renames it, and naming it `""` removes it. The 6502 already has regions for zero page, the stack and its vectors, and `acorn.bbc()` etc. name the regions of the Acorn machines' memory. `config.set_memory_region_headings(False)` turns the headings off.

:pencil:`get_label(runtime_addr, binary_addr, *, binary_addr_type: BinaryAddrType, move_id=None)`

Returns the label associated with address `runtime_addr`; it is an error to call this function if there is no such label. The `binary_addr` refers to either the definition or a usage of the label (as specified by `binary_addr_type`)

:pencil:`addr(label_name)`

Returns the runtime address of the given `label_name`.

:pencil:`set_label_maker_hook(hook)`

Sets a user supplied 'hook' function for making label names. Given an address where a label is being used, the hook function chooses a new name for the label.
The `hook` is a function that takes a single argument of class LabelMakingData. For example:

```
def my_label_maker(d):
    # This example replaces any instances of one label name with another,
    # when found between a range of binary addresses.
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
```

The hook is called once for each place a label is used or defined, so for a label used in many places it's called many times. It should decide from the `LabelMakingData` it's given (the address, where the label is used, the suggested name), not from how many times it's been called or in what order.

### Constants

:pencil:`constant(value, name, comment=None, align=Align.INLINE, format=Format.DEFAULT)`

Define a constant `name` with value `value`; think of this as being passed straight through to the output as `name = value`. The optional comment text can be `align`ed and the value can be defined as Format.DECIMAL, .DECIMAL_SIGNED, .BINARY, .HEX, .BINARY, .PICTURE_BINARY, .CHAR, .STRING, and .DEFAULT.

To illustrate the difference between labels and constants:
- If you say `label(42, "meaning_of_life")`, an `lda 42` instruction will be disassembled as `lda meaning_of_life`.
- If you say `constant(42, "meaning_of_life")`, an `lda 42` instruction will be disassembled as `lda 42`. Instead use ``expr()`` (see below) to use a constant. Example: You could use `expr()` to change `lda #42` into `lda #meaning_of_life`.

Simple rule of thumb: use `label` only for addresses, use `constant()` for everything else.

:pencil:`substitute_constants(instruction, reg, constants_dict, define_all_constants=None)`

The idea of this command is to replace load immediate numbers with constants.

For example: `substitute_constants("sta sprite_number", 'a', sprite_dict)`

Would search for any `sta sprite_number` and convert e.g.:

    lda #$15
    sta sprite_number

into:

    lda #SpriteId_Peanut
    sta sprite_number

When `instruction` is encountered, look for a load immediate instruction for register `reg` somewhere beforehand, and use the `constants_dict` dictionary to substitute a constant or expression (see below for an explanation of expressions) in place of the immediate value.

`define_all_constants` has three possible values:

    None    - define no constants (the default)
    False   - define only the constants used
    True    - define all constants

### Expressions

An expression is a string containing labels, constants and/or other arithmetic that the assembler can interpret. When the given address is reached the string expression is output instead of a regular literal value.

py8dis doesn't directly check the expression provided evaluates to the expected value found in the binary file. However, the assembly code output contains assertions that will fail if the values do not match. i.e. Careless use of `expr()` can cause py8dis to generate output which will not correctly re-assemble into its input.

:pencil:`expr(runtime_addr, s)`

When disassembling the byte at `addr`, use the string `s` instead of the literal value of that byte. Note that `addr` is the address of the byte itself, not the address of the instruction whose operand it is. `addr` might not even be part of an instruction; it might be data of some kind.

Example: `lda #$30` could be replaced with `lda #>screen_address`.

Alternatively, if s is a dictionary, then use it to substitute a constant or expression in place of the byte at `addr`.

:pencil:`expr_label(runtime_addr, s)`

Associate expression `s` with address `runtime_addr`. Any reference to `runtime_addr` in an instruction operand when disassembling will be replaced with `s`.

Example: `lda $1ee4,x` could be replaced with `lda current_level_data+1,x`

#### Making expression strings
There are functions to help construct expression strings that will work across all assemblers:

:pencil:make_op1(op, expr)

For unary operators. For example `make_op1('NOT', 'input_bits')` might return `'!input_bits'` or `'NOT(input_bits)'` depending on the assembler.

:pencil:make_op2(expr1, op, expr2)

For binary operators, e.g. `make_op2('address', 'DIV', 8)`

All the usual operators, +, -, *, / and so on can be used. It will accept common alternatives, 'AND' or '&' for example, 'XOR' or 'EOR'. These will be translated appropriately for the current assembler.

There are convenience functions for common uses of the above:

| Function                                  | Description                                                   |
| :---------------------------------------- | :------------------------------------------------------------ |
| :pencil:`make_lo(expr)`                   | for the low byte of a number                                  |
| :pencil:`make_hi(expr)`                   | for the high byte of a number                                 |
| :pencil:`make_add(expr1, expr2)`          | add                                                           |
| :pencil:`make_subtract(expr1, expr2)`     | subtract                                                      |
| :pencil:`make_multiply(expr1, expr2)`     | multiply                                                      |
| :pencil:`make_divide(expr1, expr2)`       | divide                                                        |
| :pencil:`make_or(expr1, expr2)`           | bitwise or                                                    |
| :pencil:`make_and(expr1, expr2)`          | bitwise and                                                   |
| :pencil:`make_eor(expr1, expr2)`          | bitwise eor (synonym for make_xor)                            |
| :pencil:`make_xor(expr1, expr2)`          | bitwise xor                                                   |
| :pencil:`make_modulo(expr1, expr2)`       | remainder after division                                      |

Calls can be strung together: `make_lo(make_add('level_data', 1))`


### Marking data

#### Bytes and Words

:pencil:`byte(addr, n=1, cols=None)`

Mark `n` bytes at address `addr` as byte data. If `cols` is not None, then format the output in a fixed number of columns.

:pencil:`word(addr, n=1, cols=None)`

Mark 2*`n` bytes at address `addr` as (16-bit little-endian) word data. If `cols` is not None, then format the output in a fixed number of columns.

#### Strings
Strings have different ways of terminating, so we have many functions available to help define the extent of a string. Each function marks all the bytes as a string and returns the next available address after the string.

| Function                                                       | Description                                                                        |
| :------------------------------------------------------------- | :--------------------------------------------------------------------------------- |
| :pencil:`string(addr,n=None)`                                  | The string terminates at a non-printable ASCII character, or the given length `n`. |
| :pencil:`stringterm(addr,terminator,exclude_terminator=False)` | The string terminates with a `terminator` value, and can either include or exclude the terminator from the string. |
| :pencil:`stringcr(addr,exclude_terminator=False)`              | The string terminates with ASCII code 13. |
| :pencil:`stringz(addr,exclude_terminator=False)`               | The string terminates with ASCII code zero. |
| :pencil:`stringhi(addr,include_terminator_fn=None)`            | The string terminates with a top-bit-set character, optionally including the bottom 7 bits of the terminator as the final character. A user supplied function can determine whether the terminator is included or not, based on the final character. |
| :pencil:`stringhiz(addr,include_terminator_fn=None)`           | As stringhi(), but also terminates at ASCII code zero. |
| :pencil:`stringn(addr)`                                        | The first byte holds the length of the string, followed by the string itself. |

Each of these also takes `encoding=` (e.g. `stringz(addr, encoding="screen")`) to give the string a text encoding other than the session's (see below).

#### Text encodings

By default strings are ASCII. For a Commodore program, `config.set_text_encoding("petscii")` makes PETSCII (the character codes used with CHROUT) the session's text encoding: for strings (including those `autostring()` finds), the character column of the hex dump, and the character comments on immediate operands (`lda #$41 ; 'a'`). `"screen"` is for Commodore screen codes, as stored in screen memory. A string command's `encoding=` option gives one string another encoding, e.g. `string(0xc04e, 21, encoding="screen")` for text copied straight to the screen, or `encoding="ascii"`. (Set the session's encoding before marking any strings: each string keeps the encoding it was marked with.)

The characters are those of acme's `!pet` and `!scr`, so that acme can write the strings as text, e.g. `!pet "Hello", $0d` and `!scr "Score"`. A character literal (from `char()`, or the character CHROUT outputs, see [Commodore](#commodore-64-vic-20-c128-and-plus4)) is in the session's encoding too: acme's output then starts with `!ct pet` (or `!ct scr`), which makes `lda #'a'` PETSCII, so an ASCII string in it is written with `!raw` rather than `!text` (which would be converted). beebasm and xa have no such character literals, so they're numbers with the character in a comment (`lda #$41 ; 'a'`). As in acme, lower case letters are the unshifted letters (PETSCII $41-$5A, screen codes $01-$1A) and upper case ones the shifted letters (PETSCII $C1-$DA, screen codes $41-$5A): the text as it appears in the C64's lower/upper case character set. (In the default upper case/graphics set, both appear as upper case letters or graphics.) Codes acme's character would misrepresent, such as PETSCII $5C (a pound sign on the C64, but a backslash to acme), and the graphics characters, are written as numbers. beebasm and xa have no PETSCII or screen code directives, so these strings are written as bytes with the text in a comment, e.g. `equb &c8, &45, &4c, &4c, &4f ; petscii "Hello"`.

### Marking code (and data that points to code)

:pencil:`entry(addr, label=None)`

Specifies that there is code at the given address `addr`. When `go()` is called, code is automatically traced starting from each entry point walking through all possible branches and subroutines. The bytes are marked as code, and therefore get output as instructions. If specified, `label` will be attached to `addr`; this is just a convenience to save needing to call `label()` explicitly.

:pencil:`wordentry(addr, n=1)`

Marks a sequence of `n` words as being (16-bit little endian) addresses of subroutines. This categorises the data as being words and also adds the addresses as entry points for tracing code.

:pencil:`code_ptr(addr, addr_high=None, offset=0, label=None)`

Marks two bytes of data as being the address of a subroutine. The low and high bytes do not need to be stored adjacently since their addresses can be specified separately as `addr` and `addr_high`. If `addr_high` is None, then `addr_high` is assumed to be the byte after `addr`. This function can be used to handle jump tables where the low and high bytes are stored in separate tables.

An optional offset can be applied to the data to get the subroutine address. The subroutine address is added as an entry point for code tracing.

Note that `code_ptr(addr)` and `wordentry(addr)` are equivalent.

:pencil:`rts_code_ptr(addr, addr_high=None)`

Syntactic sugar for `code_ptr(..., offset=1)`. This is intended for use with jump table entries which are used by pushing them onto the stack and executing `RTS`.

### Modifying the tracing process

See `entry()` to find out more about tracing.

:pencil:`nonentry(addr)`

Marks an address `addr` as 'not to be traced as code'. If the tracing of code reaches the given address then tracing stops. For example, when a conditional branch is in practice always taken at runtime, any following code is never executed. This command is only required occasionally.

:pencil:`hook_subroutine(subroutine_addr, name, hook)`

Tells the instruction tracing code that a call to a subroutine (using e.g. `jsr subroutine_addr`) will not necessarily return control to the instruction immediately following the `jsr`. The common use case is a subroutine that 'prints the following string', which consists of a call to a subroutine followed by a string definition. Execution only continues *after* the string definition.

When a `jsr subroutine_addr` instruction is disassembled, `hook(subroutine_addr, address of jsr instruction)` is called and the return value is used as the next instruction address to trace. The hook can return `None` to indicate tracing shouldn't continue, or it can call `entry` to indicate additional addresses to trace.

`name` is used to label `subroutine_addr`, exactly as if `entry(subroutine_addr, name)` were called.

:pencil:`stringhi_hook(target, addr)`

:pencil:`stringhiz_hook(target, addr)`

:pencil:`stringcr_hook(target, addr)`

:pencil:`stringz_hook(target, addr)`

:pencil:`stringn_hook(target, addr)`

Wrappers around `stringhi()`, `stringhiz()` etc for use with `hook_subroutine()`. These are designed for the 'print the following string' case described above.

### Number Formats

By default numerical values are formatted as decimals for single digits or hex otherwise (known as 'uint' formatting). The following functions override this format for data in the specified block.

| Function                                  | Description                                                                                |
| :---------------------------------------- | :----------------------------------------------------------------------------------------- |
| :pencil:`char(addr,n=1)`                  | Specifies quoted character (e.g. 'a', in the session's text encoding) formatting for data in the given block |
| :pencil:`binary(addr,n=1)`                | Specifies binary (e.g. %010110111) formatting for data in the given block                  |
| :pencil:`picture_binary(addr,n=1)`        | Specifies picture binary (e.g. %#.####.#) formatting for data in the given block           |
| :pencil:`decimal(addr,n=1)`               | Specifies decimal formatting for data in the given block                                   |
| :pencil:`hexadecimal(addr,n=1)`           | Specifies hex formatting for data in the given block                                       |
| :pencil:`uint(addr,n=1)`                  | Specifies unsigned int formatting for data in the given block                              |
| :pencil:`sint(addr,n=1)`                  | Specifies signed int formatting for data in the given block                                |
| :pencil:`padded_uint(addr,n=1)`           | Specifies padded uint formatting for data in the given block                               |
| :pencil:`set_formatter(addr,n,formatter)` | The `formatter` function converts a data value into a string. Used by the above functions. |

### Commentary and blank lines

:pencil:`subroutine(runtime_addr, name=None, title=None, description=None, on_entry=None, on_exit=None, hook=None, move_id=None, is_entry_point=True)`

Define a subroutine. All parameters except the address are optional. These are used to create a header comment above the definition of the subroutine. They are also used to decorate calling code with explanatory text. If this is not wanted specify `hook=False`. The subroutine is commented as below. The initial and final row of stars is configurable.

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

The `on_entry` and `on_exit` optional parameters are dictionaries that specify a comment for each register as required. e.g. `on_entry={ 'a': "number to print" }`. If a parameter description is in brackets, it is not used when decorating calls to this routine. This allows for `{ 'x': '(preserved)' }` style descriptions.

The `is_entry_point` parameter adds the address as an entry point for code.

The `hook` parameter is a callback to allow for the decoration of the calling code. If `None` (the default) a standard hook is used, which comments where registers are set up before each call and used after it; `hook=False` turns decoration off.

:pencil:`no_automatic_comment(runtime_addr)`

Disables the automatic commentary at the given address, to allow the user to write their own.

:pencil:`comment(runtime_addr, text, indent=0, word_wrap=True, align=Align.BEFORE_LABEL)`

Insert `text` as a comment at address `addr` in the disassembly. If the line has a label, it can be added before or after the Label using Align.BEFORE_LABEL or Align.AFTER_LABEL. If a line of disassembly is output at the address, the comment can be positioned before or after the line, using Align.BEFORE_LINE or Align.AFTER_LINE. If `align` is Align.INLINE, then the comment is added to the end of the line instead. If not inline, the number of indents is applied and the comment is word wrapped by default.

:pencil:`formatted_comment(addr, text, align=Align.BEFORE_LABEL, indent=0)`

As `comment` but the text is assumed to be pre-formatted and is therefore not word wrapped. Equivalent to `comment()` with `word_wrap=False`.

:pencil:`blank(addr, align=Align.BEFORE_LABEL, priority=None)`

Add a new blank line to the output at the given address. The `priority` helps order multiple items at the same address.

:pencil:`annotate(runtime_addr, s, align=Align.BEFORE_LABEL, priority=None)`

Add `s` as a raw string to the output at the given address. `s` will need to be understood by the assembler. The `priority` helps order multiple items at the same address. Rarely useful in practice since it's something of a last resort to output what you want and is likely assembler specific. Used by `blank()`.

### Memory access

:pencil:`get_u8_binary(addr)`

Returns the unsigned 8-bit byte at address `addr`.

:pencil:`get_u16_binary(addr)`

Returns the unsigned little-endian 16-bit word at address `addr`.

:pencil:`get_u16_be_binary(addr)`

Returns the unsigned big-endian 16-bit word at address `addr`.

### Relocating memory
:pencil:`move(dest, src, length)`

Indicates that a block of memory is copied at runtime.

Often a block of memory is moved (relocated) after loading the binary file but before being used at runtime. For example, BBC Micro games that load at &1900 often relocate bits of code or data, or maybe the whole file down to &e00 before use.

This function specifies such a move, indicating that the runtime address is different from the address at load time for a block of memory. This allows labels within the block to be properly defined by their runtime addresses.

Any `move()` calls must be done before accessing the relocated block.

As a simple rule, put any `move()` commands just after `load()`.


### Output the results

:pencil:`go(print_output=True, post_trace_steps=None, autostring_min_length=3)`

Classifies the binary into code and data, calculates all label names and (optionally) emits the final assembly. The output is also returned as a string. `post_trace_steps` allows the user to supply a function to find strings in the binary, overriding the default function.

:pencil:`reset()`

Forgets everything (loaded data, moves, labels, constants, comments, entry points, subroutines, hooks and settings), ready to disassemble something else in the same Python script. The command line is read again to choose the assembler and the case of the output. For example:

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

## Commodore 64, VIC-20, C128 and Plus/4

`commodore.c64()` does for a Commodore 64 program what `acorn.bbc()` does for a BBC Micro one:

```python
from commands import *
import commodore

start = load_prg("game.prg", "6510")
commodore.c64()
go()
```

It gives:

* **Names for the memory locations**, output only if used: zero page, the OS and BASIC workspace, the Kernal's and BASIC's vectors, the screen and sprite pointers, the VIC-II, the SID, the colour RAM, the CIAs and the 6510's I/O port, grouped under headings by region (e.g. `; VIC-II ($d000-$d3ff)`). The names are descriptive by default, e.g. `vic_border_colour`, `cia1_port_a`, `keyboard_buffer_length`; `commodore.c64(names="commodore")` uses the names in Commodore's documentation instead (the Programmer's Reference Guide and Commodore's source, and for the I/O registers *Mapping the Commodore 64*), e.g. `extcol`, `ciapra`, `ndx`.
* **The Kernal's jump table**, by Commodore's names (e.g. `chrout`, `setlfs`), with comments on each call and where its registers are set and used:

  ```
      lda #$0f              ; A=logical file number
      ldx #device_disk_8    ; X=device number
      ldy #$0f              ; Y=secondary address
      jsr setlfs            ; Set logical file 15 to device 8 (disk drive), secondary address 15
      lda #2                ; A=filename length
      ldx #<filename        ; X=filename address (low byte)
      ldy #>filename        ; Y=filename address (high byte)
      jsr setnam            ; Set the filename to "i0"
  ```

  CHROUT's comment names the character (`Output $93 (clear screen)`), and a printable character is written as one where it's loaded (`lda #'a'`, with acme; see [Text encodings](#text-encodings)), PLOT's and MEMTOP's say whether the call reads or sets (from the carry flag), SETNAM's filename and the string printed by BASIC's STROUT are marked as PETSCII strings, and SAVE's zero page pointer is named.
* **The ROMs' routines** that programs call (e.g. `jmp kernal_irq_handler` for &ea31, `basic_print_string` for STROUT), and all the labels in Commodore's source for the Kernal and BASIC ROMs, as optional labels. A program that replaces the ROMs should use `commodore.c64(rom_labels=False)`. Where a Kernal label in Commodore's source has the same name as a jump table entry or another name (e.g. PLOT, the routine at &e50a that `plot` at &fff0 jumps to), it has `_rom` added (`plot_rom`), and a BASIC label with the same name as another has `_basic` added (e.g. `stop_basic`, BASIC's STOP command).
* **Colours** stored in the VIC-II's colour registers or the text colour, as constants: `lda #colour_black : sta vic_border_colour`.
* **Vectors set by the program** (e.g. `lda #<x : sta $0314 : lda #>x : sta $0315`, or with X and Y): the address is traced as code and named after the vector, e.g. `irq_handler` (or `irq_handler_2` etc. for more), with a comment, `; Set the IRQ vector to irq_handler`.
* **The BASIC program** at &0801, if there is one (see `basic_program()` below).
* **PETSCII** as the text encoding (see [Text encodings](#text-encodings)). Call `c64()` before marking any strings.

Names are only used where nothing else names the address. An optional label isn't used if its name is given to another address (e.g. a control file's `label(0x0964, "key")` when Commodore's name for &ea31 is `key`), so the name isn't defined twice.

:pencil:`commodore.vic20(expansion=None, names="descriptive", rom_labels=True)`

The same for the VIC-20, whose Kernal and BASIC are the C64's with its own hardware and memory map: the VIC (`vic_background_border_colour`, `vic_voice1_frequency`…), the two VIAs (`via1_port_a`…, or Commodore's `d1ora`…), the colour RAM, the character ROM, the screen, its own ROM routines (e.g. `kernal_irq_handler` at &eabf) and the labels in Commodore's source for its ROMs. Its jump table lacks the C64's first three entries. Commodore gave the VIC's registers no names of their own, so with `names="commodore"` they're `vicreg`, `vicreg+1` and so on, as in its source.

`expansion` is the RAM expansion: `"none"`, `"3k"` (block 0, &0400-&0fff) or `"8k"` (8K or more, from &2000). It decides where a BASIC program starts (&1001, &0401 or &1201) and where the screen and its colour RAM are (&1e00 and &9600, or with 8K or more &1000 and &9400). By default it's worked out from where the program is loaded: `"3k"` if there's data at &0401, else `"none"` if there's data at &1001, else `"8k"` if there's data at &1201.

:pencil:`commodore.c128(names="descriptive", rom_labels=True)`

The same for the C128 in C128 mode, with the usual bank 15 (the ROMs, and the I/O at &d000): its workspace, the MMU (`mmu_configuration` at &ff00, `mmu_ram_configuration`…), the VDC (`vdc_address` and `vdc_data` at &d600), the VIC-II, the SID and the CIAs as on the C64, a BASIC program at &1c01, and the labels in Commodore's source for its BASIC, monitor, screen editor and Kernal (a screen editor or monitor label with the same name as another has `_editor` or `_monitor` added). Its jump table is the C64's and 19 more at &ff47-&ff7d, e.g. `jsrfar`, `setbnk` and `primm`, whose inline string is marked and skipped when tracing:

```
    jsr primm             ; Print the zero-terminated string that follows the JSR
    !pet "hello, c128", $0d, 0
```

A call to another bank with JSRFAR or JMPFAR, whose bank and address are set up at &02-&04 with immediate values (through A, X or Y, in any order, with stores to &05-&08 between them and the call), is commented, e.g. `; Call far_call_target in bank 0`. If the address is in the program, in a bank that has RAM 0 there, where the program is (banks 0 and 2, and below their ROMs, 4, 6, 8, 10 and 12-15), it's traced as code, named `far_call_target` (or `far_jump_target`, then `_2` etc.) unless it already has a name, and the set-up uses its name:

```
    ; Call far_call_target in bank 0
    lda #0
    sta far_call_bank
    lda #>far_call_target
    sta far_call_pc_high
    lda #<far_call_target
    sta far_call_pc_low
    jsr jsrfar
```

The names assume the C128's usual bank 15: the ROMs, with I/O at &d000. In another configuration of its MMU, the same addresses can be something else, e.g. RAM rather than the VIC-II or the Kernal ROM. So:

* **The code that sets the MMU's configuration is commented** with what it sets, when the value stored to its configuration register (&ff00, or &d500) is known, e.g. `sta mmu_configuration ; Set the MMU to bank 0 (RAM 0 only)`, or `; Set the MMU to RAM 0, I/O` for one that isn't one of the Kernal's 16 banks. A store to one of its load configuration registers (&ff01-&ff04) is commented too, e.g. `; Set the MMU to preconfiguration A (as set at $d501)`.
* **The code after it uses that configuration's names.** An address it uses that's something else in that configuration than in bank 15 gets a plain name there, e.g. after `lda #$3f : sta $ff00` (bank 0), `lda $d020` is `lda ld020` rather than `lda vic_border_colour`. These names are listed under their own heading, `; Other banks`, at the end of the memory locations, since their addresses' regions are bank 15's. This lasts as long as the code runs straight on: up to the end of a block (e.g. RTS or JMP), an instruction other code jumps or branches to, or the next change of configuration. (&0000-&03ff is RAM 0 in every bank, the Kernal's common RAM, so its names stay. Only the names `c128()` gives are replaced, not the control file's; and the Kernal calls keep their names and comments.)

:pencil:`commodore.c128_bank(start, end, bank=None, *, configuration=None)`

Says that the code from `start` to `end` (runtime addresses, `end` exclusive) runs with the MMU set to `bank` (0-15, as the Kernal numbers them) or `configuration` (the value of its configuration register), e.g. a routine whose caller sets the bank. The addresses it uses are named as above. (Code after a change of configuration in it follows that change.) Call it after `c128()`.

`commodore.c128_memory(configuration, addr)` says what's at an address in a configuration (e.g. `"I/O"`, `"Kernal ROM"`, `"RAM 1"`), and `commodore.c128_configuration_description(configuration)` describes a configuration, as in the comments above.

(A C128 program in C64 mode is a C64 program: use `c64()`.)

:pencil:`commodore.plus4(names="descriptive", rom_labels=True)`

The same for the Plus/4 (and the C16 and C116, which have the same ROMs): its workspace, the TED at &ff00-&ff3f (the timers, video, sound, keyboard latch, interrupts, and the ROM switch at &ff3e/&ff3f: `ted_rom_select`, `ted_ram_select`), the ACIA at &fd00, the 6529 ports, the screen and its attributes, a BASIC program at &1001, and the labels in Commodore's source for its BASIC and Kernal. Its jump table is the C64's with `print`, `primm` (as on the C128) and `monitr`. The TED's colours include their luminance, so they aren't named as constants.

The C128's and Plus/4's workspace (zero page and &0200 up) has Commodore's names from its source. With the default `names="descriptive"`, the locations that are the C64's have its descriptive names (e.g. `jiffy_clock`, `keyboard_buffer_length`), and the most used of the rest have descriptive names of their own (e.g. the C128's `screen_mode_40_80`, `vdc_screen_base`, `function_key_lengths`); the others have Commodore's names either way, since there are hundreds and most are BASIC's or the monitor's. The hardware's names are descriptive with `names="descriptive"` and Commodore's (from its source, e.g. `mmucr`, `vdcadr`, `tedirq`) with `names="commodore"`.

:pencil:`commodore.basic_program(runtime_addr=None)`

Marks the tokenised BASIC program at `runtime_addr`, by default where BASIC programs start on the machine (`c64()` etc. do this), such as the one-line `10 SYS2061` most machine code programs start with. Each line is labelled (`basic_line_10`), its link to the next line and its line number are words, and its text is bytes for the tokens and PETSCII strings, with the line listed in a comment:

```
; 10 SYS2061
basic_line_10
    !word basic_end
    !word 10
    !byte $9e
    !pet "2061"
    !byte 0
basic_end
    !word 0
```

An address that SYS calls in the loaded data is traced as code, and named `sys_entry` unless it already has a name (so to name it yourself, do so before calling `c64()`). Returns the address after the program, or None if there isn't a BASIC program there.

:pencil:`commodore.is_cartridge()`

For a cartridge: names its header (the cold and warm start vectors, and the signature: `CBM80` at &8004 on the C64, `A0CBM` at &a004 on the VIC-20) and traces the code they point to. On the C128 and Plus/4, a function ROM at &8000 starts with its cold and warm start code (usually JMPs) rather than vectors, then an ID byte and `CBM` in ASCII; these are named and the code traced. Call it after `c64()` etc.

:pencil:`commodore.kernal_rom()` and :pencil:`commodore.basic_rom()`

For disassembling a Kernal ROM (at &e000, or &c000 on the C128 and Plus/4) or BASIC ROM (at &a000 on the C64, &c000 on the VIC-20, &4000 on the C128, &8000 on the Plus/4) itself: trace the code from the Kernal's jump table and the 6502's vectors, or BASIC's cold and warm start vectors (or JMPs, on the C128 and Plus/4). examples/python/open_roms_kernal.py and open_roms_basic.py disassemble the ROMs of [MEGA65's Open ROMs](https://github.com/MEGA65/open-roms), a free replacement for the C64's.

## JSON output

As well as the asm, py8dis can write the finished disassembly as JSON, for other tools to read: for example a web page of the disassembly with links between labels and the code that uses them, a symbol table for an emulator's debugger, or a comparison of two versions of a ROM.

    python3 mycontrolfile.py --acme --json out.json              # asm printed as usual, JSON to out.json
    python3 mycontrolfile.py --acme -o out.asm --json out.json   # asm to out.asm, JSON to out.json

When using py8dis as a library, `session.new_session(json_filename="out.json")` does the same.

The JSON holds what py8dis knows once it has finished, with exactly the names used in the asm but without its layout:

- the CPU, the assembler, the files loaded and the moves;
- the constants, memory regions and subroutines;
- every label: its names and where the asm defines them, local names, expressions, and the code and data that refer to it;
- every instruction or piece of data, in address order: its addresses, bytes, labels, comments and text as in the asm. Instructions also have their mnemonic, addressing mode, operand (its value and expression), target, cycles and the CPU state; data has its values and expressions.

Expressions are given as text and as a tree, e.g. `{"op": "+", "left": {"label": 8206, "name": "message"}, "right": {"num": 1, "format": "decimal"}}`.

The format is described in [docs/json-format.md](docs/json-format.md), with a [JSON Schema](https://json-schema.org/) in [docs/py8dis-json.schema.json](docs/py8dis-json.schema.json).

## Symbol files and cross-reference listings

As well as the asm, py8dis can write a symbol file, giving each label's name and address (e.g. for an emulator's debugger), and a cross-reference listing, giving each label and everything that refers to it:

    python3 mycontrolfile.py --symbols out.sym                           # plain format
    python3 mycontrolfile.py --symbols out.lbl --symbols-format vice
    python3 mycontrolfile.py --xref out.xref

When using py8dis as a library, `session.new_session(symbols_filename=..., symbols_format=..., xref_filename=...)` does the same.

The symbol file formats are:

| `--symbols-format` | Example line          | For                                                                                   |
| ------------------ | --------------------- | ------------------------------------------------------------------------------------- |
| `plain` (default)  | `oswrch = &ffee`      | Reading, or converting to another format. In the assembler's hex syntax.               |
| `vice`             | `al 00FFEE .oswrch`   | The VICE emulator's monitor, which loads it with `ll "file"` (as cc65's `ld65 -Ln` writes). |
| `beebasm`          | `[{'oswrch':65518L}]` | Tools that read beebasm's symbol dump (`beebasm -d`).                                   |
| `mame`             | `comadd ffee,oswrch`  | MAME's debugger, which runs it with `source file`, showing each name as a comment.      |

Each name a label has is included (local label names as the asm uses them), but not constants or expressions such as `table+1`. Labels are by address. VICE and MAME can't take an address past the top of memory (such as `pydis_end`, for data that ends at &FFFF), so those names are left out of their files.

The cross-reference listing gives each label, with its names and where the asm defines them, then each instruction or piece of data that refers to it: the address, where that is (the nearest label before it, plus an offset), and its text in the asm:

    &ffe3  lffe3 (Memory locations)
        &2005     loop_c2002+3                 jsr lffe3

## Getting help

If you have problems or suggestions for improvement, you can raise an issue or submit a pull request in github. Alternatively you may like to post in the [py8dis thread](https://stardot.org.uk/forums/viewtopic.php?f=55&t=23335) on the [stardot](https://stardot.org.uk) forums.

## Credits and thanks

* py8dis is heavily influenced by Phill Harvey-Smith's [BeebDis](https://github.com/prime6809/BeebDis); I've tried to model py8dis commands on BeebDis where possible.
* The Commodore 64's names and Kernal calls in `commodore.py` come from Michael Steil's [c64ref](https://github.com/mist64/c64ref) (BSD 2-clause licence; see `commodoretables.py`), and the ROM labels (and the C128's and Plus/4's workspace) from Commodore's source in his [cbmsrc](https://github.com/mist64/cbmsrc) (see `commodoresource.py`, made by `tools/make_commodoresource.py`).
* The VIC-20 test game is Robert Hurst's [Quikman 2K8](https://github.com/theflyingape/quikman2k8) (Artistic License 2.0; see `examples/orig/quikman2k8`).
* The C128 test game is Sebastian Dechert's [memory128](https://github.com/radi0sus/memory128) (BSD 3-clause licence; see `examples/orig/memory128`).
* The Open ROMs test ROMs are from [MEGA65's Open ROMs](https://github.com/MEGA65/open-roms) (LGPL 3; see `examples/orig/open-roms`).
* TobyLobster has contributed numerous improvements to py8dis, including refactoring, code clean up, local label support and constant substitution, as well as making many helpful suggestions.
