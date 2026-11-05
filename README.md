<h1><img src="docs/logo/py8dis-banner-slim.svg" alt="py8dis" width="100%"></h1>

py8dis is a disassembler for 8-bit programs: it turns a machine code program back into assembly language that you can read, change and assemble again. It handles 6502, 65C02, 8080 and Z80 code, and knows about the BBC Micro and other Acorn machines, the Commodore 64 and other Commodore machines, the ZX Spectrum and CP/M.

You don't run py8dis on a program directly. Instead you write a short Python script, a *control file*, that tells it about the program: where it's loaded, where the code starts, and, as you work out what the program does, the names of its routines and variables, which parts are data, and comments. Each time you run the control file you get a better disassembly. Because the control file is ordinary Python, you can do anything Python can to help, such as reading a table of names from a file.

py8dis finds the code by *tracing* it: starting from the entry points you give, it follows every instruction, branch, jump and subroutine call it can reach. Everything it reaches is code, and everything else is data, which it searches for text. Its output assembles back to exactly the original program, so you can check your work, and change the program if you want to. It's written so that other 8-bit CPUs could be added without too much difficulty.

## Contents

- [Getting started](#getting-started)
- [A first disassembly](#a-first-disassembly)
- [Working on a disassembly](#working-on-a-disassembly)
- [Assemblers](#assemblers)
- [Command line options](#command-line-options)
- [Machines](#machines)
- [Examples](#examples)
- [More documentation](#more-documentation)
- [Getting help](#getting-help)
- [Credits and thanks](#credits-and-thanks)

## Getting started

py8dis needs [Python 3](https://www.python.org). There's nothing else to install: download or clone this repository, and tell Python where py8dis's code is by setting `PYTHONPATH` to its `py8dis` folder. On Linux or macOS:

``` sh
export PYTHONPATH=/home/you/src/py8dis/py8dis
```

or on Windows (this hasn't been tried):

``` bat
set PYTHONPATH=C:\Users\you\src\py8dis\py8dis
```

If you see an error like `ModuleNotFoundError: No module named 'commands'` when you run a control file, `PYTHONPATH` isn't right. (Another way round it is to keep your control files in the same folder as py8dis's code: `commands.py`, `trace.py` and so on.)

You'll also want an assembler for the CPU (see [Assemblers](#assemblers)), to assemble the disassembly again.

## A first disassembly

The `examples` folder has a tiny "Hello, world!" program for the BBC Micro, `examples/orig/helloworld.orig`, and a control file for it, `examples/python/helloworld.py`:

```python
from commands import *

# Load the program to be disassembled into the debugger's memory.
# The md5sum is optional but helps avoid confusion if there are
# multiple versions of the same program.
load(0x2000, "orig/helloworld.orig", "6502", "ba85fca1feae301af81806d3102b0851")

# Start tracing instructions at 0x2000.
entry(0x2000)

# Add extra commands here as the disassembly progresses...

# Use all the information provided to actually disassemble the program.
go()
```

That's the shape of every control file: `load()` the program, say where the code starts with `entry()`, and finish with `go()`. Run it from the `examples` folder:

``` sh
cd examples
python3 python/helloworld.py
```

and it prints the disassembly:

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
...
```

This is for the beebasm assembler, py8dis's default. Some things to notice:

- py8dis has made up names (*labels*) for the addresses the code uses: `l200e` for data at &200E, `loop_c2002` for a loop, and `lffe3` for an address outside the program. The list of "automatically generated labels" at the end is a to-do list of names to give.
- The comment at the end of each line is its address and bytes (and the bytes as characters).
- "referenced 1 time by &200b" says where a label is used from.
- py8dis found the string "Hello, world!" by itself.

## Working on a disassembly

Now make it better. &FFE3 is the BBC Micro's OSASCI call, which py8dis knows about if you tell it the program is for a BBC Micro. Give the loop and the message names, add a comment, and say that the message ends with a carriage return:

```python
from commands import *
import acorn

load(0x2000, "orig/helloworld.orig", "6502", "ba85fca1feae301af81806d3102b0851")
acorn.bbc()

entry(0x2000)
label(0x2002, "print_loop")
label(0x200e, "message")
comment(0x2000, "Print the message, one character at a time")
stringcr(0x200e)

go()
```

which gives:

```
; Memory locations

; MOS entry points (&ffb3-&fff9)
OSASCI  = &ffe3

    org &2000

; Print the message, one character at a time
.pydis_start
    ldx #0                                                            ; 2000: a2 00       ..
; &2002 referenced 1 time by &200b
.print_loop
    lda message,x                                                     ; 2002: bd 0e 20    ..
    jsr OSASCI                                                        ; 2005: 20 e3 ff     .. ; Write character
    inx                                                               ; 2008: e8          .
    cpx #&0e                                                          ; 2009: e0 0e       ..
    bne print_loop                                                    ; 200b: d0 f5       ..
    rts                                                               ; 200d: 60          `

; &200e referenced 1 time by &2002
.message
    equs "Hello, world!", &0d                                         ; 200e: 48 65 6c... Hel
.pydis_end
```

A real disassembly goes the same way, a step at a time: run the control file, read the output, work out a little more of what the program does, and add it to the control file. These are the commands you'll use most:

| Command | What it does |
| ------- | ------------ |
| `load(addr, filename, cpu)` | Loads the program (`load_prg()` for a Commodore PRG file, `load_atm()` for an Acorn Atom ATM file). |
| `entry(addr)` | Says there's code at the address, to trace from. |
| `label(addr, name)` | Names an address. |
| `comment(addr, text)` | Adds a comment (`inline=True` puts it at the end of the line). |
| `byte(addr, n)`, `word(addr, n)` | Marks data as bytes or words. |
| `string(addr, n)`, `stringz(addr)`, `stringcr(addr)` ... | Marks a string, ending in one of several ways. |
| `code_ptr(addr)`, `wordentry(addr, n)` | Marks the address of a routine (e.g. a table of routines), and traces it. |
| `subroutine(addr, name, title, ...)` | Describes a routine, with a header comment. |
| `expr(addr, "expression")` | Writes a value as an expression, e.g. `lda #>screen` instead of `lda #&30`. |
| `move(dest, src, length)` | Says the program copies part of itself somewhere else before running it. |
| `go()` | Makes the disassembly. |

All the commands are described in the [command reference](docs/commands.md), and the settings for the layout of the output in [configuration.md](docs/configuration.md).

Some tips:

- **Labels for addresses, constants for numbers.** `label()` names an address, and every instruction that uses the address gets the name. A number that isn't an address, such as a colour or a key code, is named with `constant()`, and written into an instruction with `expr()`.
- **Labels only where they're used.** `optional_label()` is like `label()`, but the label only appears if something uses it. The machine set-ups (such as `acorn.bbc()`) name hundreds of addresses this way.
- **Data that looks like code.** If py8dis traces into data (for example after a subroutine that never returns, or one that's followed by a string), see `hook_subroutine()` and `nonentry()`.
- **Code py8dis doesn't find.** Code that's only reached through a table of addresses, or an address worked out at runtime, isn't found by tracing: give it with `entry()`, `code_ptr()` or `wordentry()`.
- **Checking your work.** Expressions you give with `expr()` are checked: by py8dis, when it can work out their values, or else by the assembler, with assertions at the end of the output. So a wrong one gives an error, rather than a different program.

## Assemblers

py8dis can write its output for any of these assemblers:

| Assembler | CPUs | Command line |
| --------- | ---- | ------------ |
| [beebasm](https://github.com/stardot/beebasm) | 6502, 65C02 | `--beebasm` or `-b` (the default) |
| [Baron](https://github.com/waitingforvsync/baron) | 6502, 65C02 | `--baron` or `-r` |
| [acme](https://sourceforge.net/projects/acme-crossass/) | 6502, 65C02 | `--acme` or `-a` |
| [xa](https://www.floodgap.com/retrotech/xa/) | 6502, 65C02 | `--xa` or `-x` |
| [64tass](https://sourceforge.net/projects/tass64/) | 6502, 65C02 | `--64tass` or `-t` |
| [ca65](https://cc65.github.io/doc/ca65.html) | 6502, 65C02 | `--ca65` or `-c` |
| [z88dk-z80asm](https://z88dk.org) | 8080, Z80 | `--z88dk` or `-z` |
| [sjasmplus](https://github.com/z00m128/sjasmplus) | Z80 | `--sjasmplus` or `-s` |

For example, `python3 python/helloworld.py --acme`. How to assemble each one's output, and the few things to watch for with each, are in [assemblers.md](docs/assemblers.md). The CPUs, including the 6502's and the Z80's undocumented instructions, are in [cpus.md](docs/cpus.md).

## Command line options

A control file takes these options when you run it:

| Option | What it does |
| ------ | ------------ |
| `--beebasm`, `--acme`, ... | Which assembler to write the output for (see above). |
| `-o FILE`, `--output FILE` | Writes the output to a file, rather than printing it. |
| `-u`, `--upper` | Upper case output. |
| `-l`, `--lower` | Lower case output (the default). |
| `--json FILE` | Writes the disassembly as JSON too, for other programs to use. |
| `--symbols FILE` | Writes a symbol file too: each label and its address, e.g. for an emulator's debugger. `--symbols-format` chooses the format: `plain`, `vice`, `beebasm` or `mame`. |
| `--xref FILE` | Writes a cross-reference listing too: each label, and everything that uses it. |

These other files are described in [output-files.md](docs/output-files.md).

## Machines

Call one of these after `load()`, and py8dis names the machine's operating system calls, memory locations and hardware, comments the calls the program makes, and recognises the usual ways of doing things on that machine:

| Machine | Set-up | Details |
| ------- | ------ | ------- |
| BBC Micro, B+, Master, Electron | `acorn.bbc()`, `acorn.b_plus()`, `acorn.master()`, `acorn.electron()` | [machines/acorn.md](docs/machines/acorn.md) |
| Acorn Atom | `acorn.atom()` | [machines/acorn.md](docs/machines/acorn.md#the-acorn-atom) |
| Commodore 64, VIC-20, C128, Plus/4, PET, 1541 disk drive | `commodore.c64()`, `commodore.vic20()`, `commodore.c128()`, `commodore.plus4()`, `commodore.pet()`, `commodore.drive1541()` | [machines/commodore.md](docs/machines/commodore.md) |
| ZX Spectrum 48K | `spectrum.spectrum48()` | [machines/spectrum.md](docs/machines/spectrum.md) |
| CP/M | `cpm.cpm()` | [machines/cpm.md](docs/machines/cpm.md) |

For example, for a Commodore 64 program:

```python
from commands import *
import commodore

start = load_prg("game.prg", "6510")
commodore.c64()
go()
```

gives names such as `vic_border_colour` and `CHROUT`, comments such as `jsr SETNAM ; Set the filename to "i0"` and `sta cpu_port ; Set the memory configuration to RAM, I/O ($35)`, and lists the BASIC program at the start, if there is one (such as `10 SYS2061`), tracing the code it runs.

## Examples

`examples/python` has the control files for py8dis's tests. Most are small tests of one thing, but some are complete disassemblies of real programs, which show how a large disassembly is done:

| Control file | Program |
| ------------ | ------- |
| `planb.py`, `chuckie.py`, `starship.py` | BBC Micro games |
| `os12.py`, `basic4.py`, `dfs226.py`, `anfs418.py`, `lisp406.py` | BBC Micro and Master ROMs: the MOS, BASIC, DFS, ANFS and LISP |
| `atom_kernel.py` | the Acorn Atom's kernel ROM |
| `quikman2k8.py`, `memory128.py` | VIC-20 and C128 games |
| `open_roms_kernal.py`, `open_roms_basic.py` | MEGA65's Open ROMs, a replacement for the C64's |
| `spectrum48.py`, `opense.py` | the ZX Spectrum's ROM, and OpenSE BASIC, a replacement for it |
| `bbcbasic.py`, `zexdoc.py` | BBC BASIC (Z80) for CP/M, and the Z80 instruction exerciser ZEXDOC |

How to run all the tests is in [testing.md](docs/testing.md).

## More documentation

- [Command reference](docs/commands.md): every command for a control file.
- [Configuration](docs/configuration.md): settings for the layout and contents of the output.
- [CPUs](docs/cpus.md): the 6502, 65C02, 8080 and Z80, their undocumented instructions, and what py8dis works out about the registers.
- [Assemblers](docs/assemblers.md): how to assemble the output with each assembler.
- [Text encodings](docs/text-encodings.md): PETSCII and Commodore screen codes.
- Machines: [Acorn](docs/machines/acorn.md), [Commodore](docs/machines/commodore.md), [ZX Spectrum](docs/machines/spectrum.md), [CP/M](docs/machines/cpm.md).
- [Snippets and hooks](docs/snippets-and-hooks.md): teaching py8dis to recognise pieces of code, and to name things your way.
- [JSON, symbol files and cross-references](docs/output-files.md), and the [JSON format](docs/json-format.md).
- [Running the tests](docs/testing.md).

## Getting help

If you have a problem or a suggestion, raise an issue or make a pull request on GitHub, or post in the [py8dis thread](https://stardot.org.uk/forums/viewtopic.php?f=55&t=23335) on the [stardot](https://stardot.org.uk) forums.

## Credits and thanks

* py8dis is heavily influenced by Phill Harvey-Smith's [BeebDis](https://github.com/prime6809/BeebDis); I've tried to model py8dis commands on BeebDis where possible.
* The Commodore 64's names and Kernal calls in `commodore.py` come from Michael Steil's [c64ref](https://github.com/mist64/c64ref) (BSD 2-clause licence; see `commodoretables.py`), and the ROM labels (and the C128's and Plus/4's workspace) from Commodore's source in his [cbmsrc](https://github.com/mist64/cbmsrc) (see `commodoresource.py`, made by `tools/make_commodoresource.py`).
* The PET's ROM labels and workspace are from Martin Hoffmann-Vetter's reconstructions of Commodore's source, in cbmsrc, and the 1541's DOS ROM labels and workspace from the reconstructions of its source there.
* The ZX Spectrum's ROM routine names in `spectrumtables.py` are those of *The Complete Spectrum ROM Disassembly* (Ian Logan and Frank O'Hara, Melbourne House, 1983), with their addresses from Geoff Wearmouth's assembly listing of the ROM. The 48K ROM used as a test is copyright Amstrad plc, who have kindly given their permission for its redistribution but retain that copyright (see `examples/orig/spectrum48`).
* The Acorn Atom's OS calls, vectors and workspace in `acornatomtables.py` are from Acorn's *Atomic Theory and Practice* (chapter 25, as on [mdfs.net](https://mdfs.net/Docs/Comp/Acorn/Atom/atap25.htm)) and the commented Atom kernel disassembly in Andre Weissflog's [emu-info](https://github.com/floooh/emu-info), checked against the kernel ROM. The kernel ROM used as a test (`examples/orig/atom_kernel.orig`, as in the Atom emulators' ROM sets) is Acorn's.
* The CP/M BDOS functions' names, in `cpm.py`, are Digital Research's, as listed in John Elliott's [CP/M information archive](https://www.seasip.info/Cpm/bdos.html).
* The Z80 test programs are R.T. Russell's [BBC BASIC (Z80)](https://github.com/jblang/bbcbasic-z80) for CP/M (zlib licence; see `examples/orig/bbcbasic`), Frank D. Cringle's Z80 instruction exerciser [ZEXDOC](https://github.com/agn453/ZEXALL) (GPL 2; see `examples/orig/zexdoc`) and [OpenSE BASIC](https://zxdesign.itch.io/opense), a replacement ZX Spectrum ROM by Source Solutions, Inc. (GPL 2 or CC BY-SA 3.0; see `examples/orig/opense`).
* The VIC-20 test game is Robert Hurst's [Quikman 2K8](https://github.com/theflyingape/quikman2k8) (Artistic License 2.0; see `examples/orig/quikman2k8`).
* The C128 test game is Sebastian Dechert's [memory128](https://github.com/radi0sus/memory128) (BSD 3-clause licence; see `examples/orig/memory128`).
* The Open ROMs test ROMs are from [MEGA65's Open ROMs](https://github.com/MEGA65/open-roms) (LGPL 3; see `examples/orig/open-roms`).
* TobyLobster has contributed numerous improvements to py8dis, including refactoring, code clean up, local label support and constant substitution, as well as making many helpful suggestions.

py8dis is released under the MIT licence (see `LICENSE`).
