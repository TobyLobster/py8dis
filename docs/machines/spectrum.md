# ZX Spectrum

For a 48K ZX Spectrum program, load it as Z80 code and add `spectrum.spectrum48()`:

```python
from commands import *
import spectrum

load(0x8000, "game.bin", "z80")
spectrum.spectrum48()
entry(0x8000)
go()
```

## What it does

**Names the system variables**, if the program uses them, as in the Spectrum's manual, in lower case (e.g. `frames`, `last_k`, `err_sp`; `frames+1` etc. for the bytes after the first), and the screen, the attributes and the printer buffer (`screen`, `attributes`, `printer_buffer`), under headings by region.

The ROM keeps IY at ERR_NR's address, $5C3A, so a system variable addressed with IY is written as an offset from it, e.g. `res 5,(iy+flags - err_nr)` (unless the code is known to have set IY to something else).

**Names the ROM's routines and tables**, by the names in *The Complete Spectrum ROM Disassembly* (e.g. `cls`, `chan_open`, `pr_string`, `print_fp`, from CLS, CHAN-OPEN etc.). The calculator's ABS, NOT and OR are `fp_abs`, `fp_not` and `fp_or`, since sjasmplus takes `abs`, `not` and `or` to be its operators. Calls to the commonly used ones are commented, e.g. `call cls ; Clear the screen`. `spectrum48(rom_labels=False)` leaves these out (e.g. for a replacement ROM, whose routines are elsewhere).

**RST $10** (print a character) is commented with what's printed, when A is known: `Print 'A'`, `Print $0D (ENTER)`, `Print $16 (AT)`, then `Print 10 (AT's line)` and `Print 5 (AT's column)` for its parameters.

**RST $08** (an error) is followed by the error number, which is marked as a byte with the report in a comment (`Report 9 STOP statement`). The code doesn't continue after it.

**RST $28** (the floating point calculator), and calls to GEN-ENT-1 and GEN-ENT-2, are followed by the calculator's bytecode. This is marked as bytes, each with its instruction's name in a comment (`multiply`, `stk-data`, `end-calc`), its jumps as `label - $`, and its numbers (in the calculator's compressed format) with their values. The code continues after the end-calc.

**The ULA's port**, $FE, is named `ula_port`, with what's written to it commented when it's known (`out (ula_port),a ; Border blue`, with MIC and the speaker), and which keyboard half rows are read (`in a,(ula_port) ; Read the keyboard (SPACE-B)`). This is for `out (n),a` and `in a,(n)`, and for `out (c),r` and `in r,(c)` when C is even.

**A channel's routine set by the code** is followed: the output or input routine of the current channel (`ld hl,(curchl) : ld (hl),e : inc hl : ld (hl),d`) or of channel K, S, R or P (from `chans`), with the address loaded into DE before (`ld de,routine`, perhaps before a jump or call to the code that stores it). The routine is traced, named in the `ld de`, and commented, e.g. `ld de,my_print ; Set the current channel's output routine to my_print`.

## Disassembling the ROM

`spectrum.rom()`

For disassembling the 48K ROM itself (loaded at 0, after `spectrum48()`): it traces the ROM's code from the restarts, the interrupt, the NMI and its tables of routines, marks its data (the tokens, the messages, the calculator's constants and the character set) and names every routine and table. See `examples/python/spectrum48.py`.

For a ROM with the same kinds of table at other addresses (e.g. a replacement ROM), the functions `rom()` uses for them are there to call:

| Function | For |
| -------- | --- |
| `spectrum.offset_table(addr, n)` | offsets to routines, e.g. `defb L0A5F - $` |
| `spectrum.keyed_offset_table(addr, n=None)` | pairs of a character and an offset, ending with a zero |
| `spectrum.offset_entry(addr, code=True)` | one offset |
| `spectrum.syntax_table(addr, routine_classes=(0, 3, 5), last_classes=(2, 7, 11))` | a command's parameter classes, ending with the address of its routine or not |
| `spectrum.stringhi_list(addr, end)` | text, each item ending with a character with bit 7 set |

See `examples/python/opense.py`, for OpenSE BASIC.
