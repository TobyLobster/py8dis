# Apple II

For a program for the Apple II+ or IIe, use `apple.apple2()` after loading it:

```python
from commands import *
import apple

start = load_apple_file("GAME#062000")
apple.apple2()
entry(start)
go()
```

Apple II files are loaded with [`load_apple_file()`](../commands.md#load_apple_file) (an AppleSingle file, as cc65 makes, or a file whose name gives its type and address, as CiderPress names them), [`load_dos33_binary()`](../commands.md#load_dos33_binary) (a DOS 3.3 binary file with its 4-byte header), or `load()`.

`apple.apple2(model="ii+", names="apple")` takes:

- `model`: `"ii+"` (the default), or `"iie"` for the unenhanced IIe, which adds the IIe's status switches and its 80-column firmware's `AUXMOVE` and `XFER`. Both have a 6502 (or `"6510"` for a program with the undocumented opcodes). The enhanced IIe and the IIc, which have a 65C02, aren't supported yet.
- `names`: `"apple"` (the default) for Apple's names, as in its reference manuals, in capitals: `COUT`, `HOME`, `CH`, `CSWL`, `KBD`, `TXTCLR`. `config.set_upper_case_os_calls(False)`, before `apple.apple2()`, gives them in lower case. `"descriptive"` gives py8dis's own names instead: `print_char`, `clear_screen`, `cursor_column`, `output_hook`, `keyboard`, `show_graphics`.

## What it does

**Makes high ASCII the text encoding.** The Apple II's ROM, keyboard and screen use ASCII with bit 7 set, so `apple.apple2()` makes it the session's text encoding (see [text-encodings.md](../text-encodings.md)): strings like `$C8 $C5 $CC $CC $CF` are text ("HELLO"), and so is the hex dump.

**Names the Monitor's routines**, if the program uses them: `PLOT`, `HLINE`, `VLINE`, `CLRSCR`, `SETCOL`, `SCRN`, `PRNTAX`, `PRBL2`, `PREAD`, `INIT`, `SETTXT`, `SETGR`, `SETWND`, `TABV`, `SETPWRC`, `BASCALC`, `BELL1`, `VIDOUT`, `VTAB`, `VTABZ`, `CLREOP`, `HOME`, `CR`, `LF`, `SCROLL`, `CLREOL`, `WAIT`, `NXTA1`, `RDKEY`, `KEYIN`, `RDCHAR`, `GETLN`, `GETLN1`, `CROUT`, `PRBYTE`, `PRHEX`, `COUT`, `COUT1`, `MOVE`, `SETINV`, `SETNORM`, `SETKBD`, `INPORT`, `SETVID`, `OUTPORT`, `BELL`, `SAVE`, `RESTORE`, `IORTS`, `MON`, `MONZ` and others (see `apple2_monitor_routines` in `py8dis/appletables.py`). On the IIe, `AUXMOVE` ($C311) and `XFER` ($C314) too.

**Comments the calls** with what each routine does, e.g. `jsr HOME ; Clear the window and put the cursor at its top left`, where the registers it takes are set (`; A=row (0-47)`) and where what it returns is used (`; X=line's length` after `GETLN`). When a register's value is known, the comment says more:

| Routine | Comment |
| ------- | ------- |
| `COUT`, `COUT1`, `VIDOUT` | `Print 'A'`, `Print a carriage return`, `Print Ctrl-D (to start a DOS command)` |
| `PRBL2` | `Print 5 spaces` |
| `TABV`, `VTABZ` | `Move the cursor to row 10` |
| `SETWND` | `Set the text window to the full width, from row 20 down` |
| `SETCOL` | `Set the lo-res colour to 9 (orange)` |
| `WAIT` | `Wait 11,117 cycles (about 10.9 ms)` (A=$40) |
| `OUTPORT`, `INPORT` | `Send output to slot 1 (PR#1)`, `Take input from slot 2 (IN#2)` |
| `PREAD` | `Read paddle 0` |

A character printed with `COUT` is written as one where it's loaded: `lda #'A' | $80` (as the assembler writes a high ASCII character literal).

**Comments what's printed** with `COUT` (and `COUT1`, `VIDOUT`, `CROUT`, `CROUT1` and `BELL`), however A is set: a run of characters as `; Print "HELLO"`, and a DOS command, printed after a Ctrl-D, as `; DOS command: BLOAD GAME`. A loop that prints a message a character at a time is commented `; print message`.

**Names the workspace**: the Monitor's zero page (`WNDLFT`, `WNDWDTH`, `WNDTOP`, `WNDBTM`, `CH`, `CV`, `GBASL`/`GBASH`, `BASL`/`BASH`, `BAS2L`/`BAS2H`, `H2`, `V2`, `MASK`, `COLOR`, `MODE`, `INVFLG`, `PROMPT`, `YSAV`, `YSAV1`, `CSWL`/`CSWH`, `KSWL`/`KSWH`, `PCL`/`PCH`, `A1L` to `A4H`, `A5L`, `ACC`, `XREG`, `YREG`, `STATUS`, `SPNT`, `RNDL`/`RNDH`), the input buffer (`IN`, `IN+1` etc.) and the page 3 vectors (`BRKV`, `SOFTEV`, `PWREDUP`, `AMPERV`, `USRADR`, `NMI`, `IRQLOC`).

**Follows code that sets a vector**, or the output or input hook: when both bytes of `CSWL`/`CSWH`, `KSWL`/`KSWH`, `BRKV`, `SOFTEV`, `IRQLOC`, or the address in the `&`, Ctrl-Y or NMI JMP, are set, the handler is traced and named (`output_handler`, `input_handler`, `brk_handler`, `reset_handler`, `irq_handler`, `ampersand_handler`, `ctrl_y_handler`, `nmi_handler`, then `_2` etc.), and the code is commented:

```
    ; Set the output hook (CSW) to 'output_handler'
    lda #<output_handler
    sta CSWL
    lda #>output_handler
    sta CSWH
```

**Names the soft switches** at $C000-$C0FF (`KBD`, `KBDSTRB`, `TAPEOUT`, `SPKR`, `STROBE`, `TXTCLR`, `TXTSET`, `MIXCLR`, `MIXSET`, `TXTPAGE1`, `TXTPAGE2`, `LORES`, `HIRES`, `CLRAN0` to `SETAN3`, `TAPEIN`, `BUTN0` to `BUTN2`, `PADDL0` to `PADDL3`, `PTRIG`) and `CLRROM` ($CFFF), and on the IIe its status switches (`RDLCBNK2`, `RDLCRAM`, `RDRAMRD`, `RDRAMWRT`, `RDCXROM`, `RDALTZP`, `RDC3ROM`, `RD80STORE`, `RDVBLBAR`, `RDTEXT`, `RDMIXED`, `RDPAGE2`, `RDHIRES`, `RDALTCHAR`, `RD80VID`). The language card's switches are `ROMIN` ($C081), `LCBANK2` ($C083) and `LCBANK1` ($C08B), and, since Apple's documentation has no names for the others, `lc_read_ram_2` ($C080), `lc_read_rom` ($C082), `lc_read_ram_1` ($C088), `lc_read_rom_write_ram_1` ($C089) and `lc_read_rom_1` ($C08A). $C000-$C0FF is marked as I/O, so these are always defined as `name = value`.

**Comments what the code does with them**:

- An access to a switch that acts whether it's read or written: `bit TXTCLR ; Show graphics`, `lda SPKR ; Click the speaker`, `sta KBDSTRB ; Clear the keyboard strobe`, `Show page 2`, `Show hi-res graphics`, `Turn annunciator 0 on`, `Start the paddles' timers`, `Release the expansion ROM ($C800-$CFFF)`.
- The language card: `lda LCBANK2 ; Language card: read and write RAM bank 2 (two reads in a row enable writing)`, `Language card: read ROM, no writing` and so on.
- A read of an input: `Test button 0 (bit 7 set if it's pressed)` (on the IIe, `Test the Open Apple key`), `Test paddle 0's timer (bit 7 set until it runs out)`, and on the IIe `Test whether 80 columns are shown (bit 7)` etc. A loop reading `KBD` until bit 7 is set is `Wait for a key`, and on the IIe, one reading `RDVBLBAR` is `Wait for the vertical blank` or `Wait for the vertical blank to end`.

**Names the IIe's switches at $C000-$C00F where they're written.** Reading these addresses reads the keyboard, but writing them sets the IIe's memory and display switches, so each write gets the switch's name, with a comment, while reads keep `KBD`:

```
    sta SET80VID            ; Show 80 columns
    sta SET80STORE          ; Use page 2 for auxiliary memory (80STORE on)
    sta WRCARDRAM           ; Write auxiliary memory ($0200-$BFFF)
```

The names are `CLR80STORE`, `SET80STORE`, `RDMAINRAM`, `RDCARDRAM`, `WRMAINRAM`, `WRCARDRAM`, `SETSLOTCXROM`, `SETINTCXROM`, `SETSTDZP`, `SETALTZP`, `SETINTC3ROM`, `SETSLOTC3ROM`, `CLR80VID`, `SET80VID`, `CLRALTCHAR` and `SETALTCHAR` (with descriptive names such as `store_80_on`, `write_aux_ram` and `show_80_columns`). (The newer manuals call the first `80STOREOFF` and so on, which can't be a label, since it starts with a digit.)

**Names the Disk II's switches where they're indexed by the slot.** A card's I/O is at $C080 plus the slot number times 16, so code reaches the Disk II in any slot with the slot times 16 in X or Y (e.g. `ldx #$60` for slot 6). An access to $C080-$C08F indexed by X or Y is taken to be the Disk II's, and named, with a comment, as in DOS 3.3's RWTS: `PHASEOFF`, `PHASEON` (and `PHASE1OFF` to `PHASE3ON`), `MOTOROFF`, `MOTORON`, `DRV0EN`, `DRV1EN`, `Q6L`, `Q6H`, `Q7L` and `Q7H`:

```
    lda MOTORON,x           ; Disk II: turn the motor on
    lda Q7L,x               ; Disk II: Q7 low (read mode)
loop
    lda Q6L,x               ; Disk II: Q6 low (read the data latch)
    bpl loop
```

These names are only for those instructions (the same addresses without an index are the language card's), and they're listed under their own heading, `; Disk II (indexed by the slot times 16)`. Another card used the same way gets the Disk II's names too.

**Groups the memory locations** in the output by region: zero page, the stack, the input buffer, page 3, the DOS vectors, the vectors, the text and lo-res pages, the hi-res pages, the soft switches, the language card, the slots' I/O and ROMs, the expansion ROM, and the Applesoft and Monitor ROMs.

The tables are in `py8dis/appletables.py`, and a control file can use them as e.g. `apple.apple2_monitor_routines`. Apple's names were checked against the symbol files of Andy McFadden's [6502bench SourceGen](https://github.com/fadden/6502bench).
