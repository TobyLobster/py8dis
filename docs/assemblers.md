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
