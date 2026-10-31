# JSON, symbol files and cross-references

As well as the assembly language, py8dis can write the disassembly in other forms, for other tools to use.

## JSON

The JSON output is the finished disassembly as data, for other tools to read: for example a web page of the disassembly with links between labels and the code that uses them, a symbol table for an emulator's debugger, or a comparison of two versions of a ROM.

    python3 mycontrolfile.py --acme --json out.json              # the asm printed as usual, the JSON to out.json
    python3 mycontrolfile.py --acme -o out.asm --json out.json   # the asm to out.asm, the JSON to out.json

When using py8dis as a library, `session.new_session(json_filename="out.json")` does the same.

The JSON holds what py8dis knows once it has finished, with exactly the names used in the asm but without its layout:

- the CPU, the assembler, the files loaded and the moves;
- the constants, memory regions and subroutines;
- every label: its names and where the asm defines them, local names, expressions, and the code and data that refer to it;
- every instruction or piece of data, in address order: its addresses, bytes, labels, comments and text as in the asm. Instructions also have their mnemonic, addressing mode, operand (its value and expression), target, cycles and the CPU state; data has its values and expressions.

Expressions are given as text and as a tree, e.g. `{"op": "+", "left": {"label": 8206, "name": "message"}, "right": {"num": 1, "format": "decimal"}}`.

The format is described in [json-format.md](json-format.md), with a [JSON Schema](https://json-schema.org/) in [py8dis-json.schema.json](py8dis-json.schema.json).

## Symbol files

A symbol file gives each label's name and address, e.g. for an emulator's debugger:

    python3 mycontrolfile.py --symbols out.sym                           # plain format
    python3 mycontrolfile.py --symbols out.lbl --symbols-format vice

When using py8dis as a library, `session.new_session(symbols_filename=..., symbols_format=...)` does the same.

| `--symbols-format` | Example line          | For |
| ------------------ | --------------------- | --- |
| `plain` (default)  | `OSWRCH = &ffee`      | Reading, or converting to another format. In the assembler's hex syntax. |
| `vice`             | `al 00FFEE .OSWRCH`   | The VICE emulator's monitor, which loads it with `ll "file"` (as cc65's `ld65 -Ln` writes). |
| `beebasm`          | `[{'OSWRCH':65518L}]` | Tools that read beebasm's symbol dump (`beebasm -d`). |
| `mame`             | `comadd ffee,OSWRCH`  | MAME's debugger, which runs it with `source file`, showing each name as a comment. |

Each name a label has is included (local labels as the asm names them), but not constants, or expressions such as `table+1`. The labels are in address order. VICE and MAME can't take an address past the top of memory (such as `pydis_end`, for data that ends at &FFFF), so those names are left out of their files.

## Cross-reference listings

A cross-reference listing gives each label, then everything that refers to it:

    python3 mycontrolfile.py --xref out.xref

When using py8dis as a library, `session.new_session(xref_filename=...)` does the same.

For each label, it gives its names and where the asm defines them, then each instruction or piece of data that refers to it: the address, where that is (the nearest label before it, plus an offset), and its text in the asm:

    &ffe3  lffe3 (Memory locations)
        &2005     loop_c2002+3                 jsr lffe3
