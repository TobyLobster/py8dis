# Assemblers

py8dis writes its output for one of these assemblers, chosen on the command line:

| Assembler                                                | CPUs           | Command line          | Tested with |
| -------------------------------------------------------- | -------------- | --------------------- | ----------- |
| [beebasm](https://github.com/stardot/beebasm)            | 6502, 65C02    | `--beebasm` or `-b` (the default) | |
| [Baron](https://github.com/waitingforvsync/baron)        | 6502, 65C02    | `--baron` or `-r`     | v0.6.0 |
| [acme](https://sourceforge.net/projects/acme-crossass/)  | 6502, 65C02    | `--acme` or `-a`      | |
| [xa](https://www.floodgap.com/retrotech/xa/)             | 6502, 65C02    | `--xa` or `-x`        | |
| [64tass](https://sourceforge.net/projects/tass64/)       | 6502, 65C02    | `--64tass` or `-t`    | 1.59.3120 |
| [ca65](https://cc65.github.io/doc/ca65.html)             | 6502, 65C02    | `--ca65` or `-c`      | V2.18 (Ubuntu's cc65 2.19) |
| [Merlin 32](https://brutaldeluxe.fr/products/crossdevtools/merlin/) | 6502, 65C02 | `--merlin32` or `-m` | v1.1.10 |
| [z88dk-z80asm](https://z88dk.org)                        | 8080, Z80      | `--z88dk` or `-z`     | v2.4 |
| [sjasmplus](https://github.com/z00m128/sjasmplus)        | Z80            | `--sjasmplus` or `-s` | v1.24.0 |

Each disassembly is meant to assemble back to exactly the original program. py8dis's tests check this for every assembler (see [testing.md](testing.md)).

A few things are worth knowing about each one.

## beebasm

The output assembles with `beebasm -i program.asm -o program.bin`. It ends with a `save` command for the program (`pydis_start` to `pydis_end`); `set_output_filename()` puts a file name in it. A block that runs somewhere else (see `move()`) is assembled for its runtime address with `copyblock`.

beebasm, Baron and xa have no directives for PETSCII or Commodore screen codes, so strings in those encodings are written as bytes, with the text in a comment (see [text-encodings.md](text-encodings.md)).

## Baron

Baron is the spiritual successor to beebasm, by its author. Its syntax is mostly beebasm's, but its output is organised in *sections*, rather than with beebasm's `org` and `save`. So py8dis's output is one section, which holds the whole program:

```
SECTION pydis, org = &2000, filename = "game"
    ...
ENDSECTION
```

Assemble it with `baron -p . program.asm`, which writes the program to the file named in the section, in the folder given with `-p` (here, the current one). The output starts with a comment saying the command and the file. The file's name is the one given with `set_output_filename()`, or else the name of the asm file written with `-o`, without its extension (e.g. `game` for `-o game.asm`), or else `pydis`.

The rest of the output differs from beebasm's in a few ways:

- **65C02 code:** the section has `cmos = TRUE`, rather than beebasm's `cpu 1`.
- **Another range of addresses:** a later range (from a second `load()`) is reached with `SKIPTO`, which pads with zeroes.
- **Moved code:** a block that runs somewhere else (see `move()`) is a section inside the main one, with its own address, e.g. `SECTION move_1, org = &0900` … `ENDSECTION`. Its bytes go where it's written, and its labels have its runtime addresses.
- **Assertions:** they're Baron's own, `ASSERT (expr) = value`, which it checks.
- **Low and high bytes:** `<` and `>` apply to the whole of the rest of an expression in Baron (`<x+1` is the low byte of `x+1`), so py8dis adds brackets where they're part of a larger one, e.g. `(<table) + 1`.
- **Operands starting with a bracket:** Baron takes one to be indirect, so an operand like `(table+1)*2,y` is written `+(table+1)*2,y`.
- **Character literals:** a single quote can't be written as one, so it's a number, `&27`. A double quote in a string is written `""`.
- **Included files:** Baron looks for an included file (see `include_binary_file()`) relative to the asm file, so with `-o`, py8dis writes its path relative to the asm file's folder.

**Names:**

- A label can have any name, but a name defined with `=` (e.g. in the memory locations at the top) can't start with one of Baron's mnemonics or directives. So for one of these, py8dis writes an `@` before the name, e.g. `@next = &70`; it's used without the `@`.
- `TRUE`, `FALSE` and `PI` are Baron's constants, so py8dis stops with an error for a label with one of these names, in any case. Rename it.

As with beebasm, the 6502's undocumented opcodes, and an absolute instruction with a zero page address, are written as data, since Baron has no way to write them.

Baron isn't packaged, and its only release binary is for Windows, but it builds from [its source](https://github.com/waitingforvsync/baron) with CMake on Linux, macOS and Windows:

``` sh
git clone --recurse-submodules --branch v0.6.0 https://github.com/waitingforvsync/baron.git
cmake -S baron -B baron/build -DCMAKE_BUILD_TYPE=Release
cmake --build baron/build
```

which makes `baron/build/src/baron`.

## acme

The output assembles with `acme -o program.bin program.asm` (or `set_output_filename()` gives the file name for acme's `!to`). A block that runs somewhere else is in a `!pseudopc` block. For the 6502's undocumented opcodes, the output starts with `!cpu 6510` (see [cpus.md](cpus.md)).

## xa

The output assembles with `xa program.asm -o program.bin`. xa has no assert directive, so the assertions at the end use its preprocessor instead (`#if`, `#error`, `#endif`); string values aren't checked.

## 64tass

Assemble the output with `64tass -b`, which writes a plain binary. (By default 64tass writes a two-byte load address first. For a PRG file loaded with `load_prg()`, py8dis's output already has one.)

64tass looks for a file included with `.binary` (see `include_binary_file()`) relative to the asm file, so if that's somewhere else, add `-I` with the folder it's relative to.

64tass takes a label starting with `_` to be local to the label before it, so py8dis stops with an error if one is used with 64tass. Rename it.

Its encodings for PETSCII and screen codes are in [text-encodings.md](text-encodings.md#64tass).

## ca65

ca65 (part of [cc65](https://cc65.github.io)) makes an object file, which its linker, ld65, makes into a binary with a configuration file. The output starts with a comment saying how:

```
cl65 -t none -C ca65.cfg -o program.bin program.asm
```

where `ca65.cfg` (as in `examples/ca65.cfg`) gives a plain binary of the bytes in order. The `-t none` matters: cl65's default target is the C64, whose character map would change the strings.

ca65 doesn't accept a register's name (`a`, `x`, `y`), `z`, or one of the CPU's mnemonics as a label, so py8dis stops with an error for one. Rename it.

Its character map for PETSCII and screen codes is in [text-encodings.md](text-encodings.md#ca65).

## Merlin 32

Merlin 32 is Brutal Deluxe's cross-assembler in the syntax of Merlin 8 and Merlin 16, the Apple II's best-known assemblers. Assemble the output with:

```
merlin32 program.asm
```

which writes the program to a file named after the asm file without its extension (`program`), in the same folder, with `_FileInformation.txt` (its ProDOS file type) beside it. The output starts with a comment saying so.

The output is in Merlin's syntax: a label in the first column, then `EQU`, `ORG`, `DFB`, `DA`, `ASC`, `DS`, `PUTBIN` and `ERR`. It differs from the other assemblers' in a few ways:

- **Expressions:** Merlin works them out strictly from left to right (`2+3*4` is 20), and groups them with `{` and `}`, not brackets. So `a + b * c` is written `a + {b * c}`, and `(a + b) * c` is written `a + b * c`. AND, OR and EOR are `&`, `.` and `!`. It has no MOD (py8dis stops with an error for one, as for xa), no NOT (it's written `x ! $ffffffff`) and no shifts (a shift by a number is written as a multiplication or division, e.g. `x * $0100`).
- **Low and high bytes:** `<` and `>` apply to the whole of the rest of an operand, and can only start it, so in a larger expression they're written `x & $ff` and `x & $ffff / $0100`. In an address operand (not an immediate one), Merlin 32 takes `>` to choose the 65816's long addressing, so an address that starts with a high byte is written that way too.
- **Absolute addressing** for a zero page address is forced with `:` after the mnemonic, e.g. `lda: l0070,x`.
- **Zero page labels:** Merlin 32 takes a label defined in the code to be an absolute address, even after it's defined, and so is one defined with four hex digits (`$0070`). So a zero page label that a zero page instruction uses is always defined at the top, with two hex digits (`l0070 EQU $70`).
- **Another range of addresses, and moved code:** `ORG` sets the address the code is assembled for, but the bytes still follow on in the output. So a gap before a later range (from a second `load()`) is filled with `DS`, and a block that runs somewhere else (see `move()`) is just an `ORG` with its runtime address, then another with its address in the binary after it.
- **Branches round memory:** a branch whose target wraps round the top or bottom of memory can't be written at all, so it's written as data bytes, with the offset worked out from the target's label and the branch in a comment, e.g. `dfb $30, {l0020-*-2} & $ff ; bmi l0020`.
- **Strings:** `ASC 'Hello'` for ASCII, and `ASC "HELLO"` for the Apple II's high ASCII (which sets bit 7 of each character, see [text-encodings.md](text-encodings.md#merlin-32)). A string can't contain its own quote, so that's a number, as are the bytes that aren't characters. Merlin 32 reads those numbers as hex, two digits each, as `HEX` does, so they're written in hex (`$0d`), never as a constant's name or an expression.
- **Character literals:** `'A'`, or `"A"` with bit 7 set. A single quote, a comma, `{` or `}` can't be written as one, so it's a number.
- **Assertions:** `ERR expression - value`, which stops Merlin 32 unless it's 0. One that uses the current address (`*`) is left out, since it would be checked at the end of the file.
- **Included files:** `PUTBIN` finds the file relative to the asm file, so with `-o`, py8dis writes its path relative to the asm file's folder (as for Baron).
- **Inline comments:** Merlin 32 takes a `;` straight after an operand to be part of it, so a line that reaches the comments' column has a space before its comment.

The 6502's undocumented opcodes are written as data, as for beebasm, Baron and xa. 65C02 code needs nothing extra.

Merlin 32 doesn't accept a register's name (`a`, `x`, `y`) as a label (`x` would replace the index register in `lda table,x`), so py8dis stops with an error for one. Rename it.

An expression given as text (e.g. to `expr()`) is written as it is, so it has to be in Merlin's syntax, with `{` and `}` rather than brackets. A control file can get the assembler's brackets with `config.get_assembler().expression_brackets()` (see `examples/python/starship.py`), or make the expression with `make_add()` etc., which write it for each assembler.

Merlin 32 isn't packaged, but it builds from [its source](https://github.com/lroathe/merlin32) on Linux and macOS with `make -C Source` (its v1.1.11 tag, which reports itself as v1.1.10).

## z88dk-z80asm

Assemble the output with `z88dk-z80asm -m8080 -b` for 8080 code, or `-mz80 -b` for Z80 code. (`--z88dk-8080` and `-8`, the names from before the Z80 was added, still work.)

For the Z80, it accepts the undocumented instructions listed in [cpus.md](cpus.md#the-z80). z88dk-z80asm has no assertions of its own, so the assertions at the end are comments.

## sjasmplus

The output starts with a comment saying how to assemble it to a plain binary:

```
sjasmplus --nologo --raw=program.bin program.asm
```

It's for the Z80 only, since sjasmplus has no Intel 8080 mnemonics. It accepts the same undocumented instructions as z88dk-z80asm; if `out (c),0` is used, the output turns off sjasmplus's warning about it (`OPT -Wno-out0`).

A block that runs somewhere else (see `move()`) is a `DISP` block, the low and high bytes of an expression are `low x` and `high x`, and the assertions at the end are sjasmplus's `ASSERT`s, which it checks.

sjasmplus doesn't accept these as labels, so py8dis stops with an error for one (rename it):

- a register's or a condition's name (e.g. `hl`, `c`, `nz`);
- one of its operators that's a word (`and`, `or`, `xor`, `mod`, `low`, `high`, `not`, `shl`, `shr`, `abs`, `exist`, `sizeof`, `norel`, `pair`, `u16`, in any case);
- a name longer than 64 characters.

sjasmplus isn't packaged for Ubuntu, but it builds from [its source](https://github.com/z00m128/sjasmplus) on Linux and macOS with `make USE_LUA=0`.
