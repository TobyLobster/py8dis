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

**Names Applesoft's routines and zero page.** The II+ and IIe have Applesoft in ROM, and machine code called from BASIC (with CALL, `&` or USR) often uses its routines, so these are named too, by the names in Applesoft's source: `CHRGET` and `CHRGOT` (in zero page), `ERROR`, `RESTART`, `INLIN`, `NEWSTT`, `STROUT`, `STRPRT`, `OUTSP`, `OUTQUES`, `OUTDO`, `FRMNUM`, `FRMEVL`, `CHKCLS`, `CHKOPN`, `CHKCOM`, `SYNCHR`, `SYNERR`, `PTRGET`, `BASIC` and `BASIC2` (the cold and warm starts), `IQERR`, `GIVAYF`, `SNGFLT`, `GETBYT`, `CONINT`, `GETNUM`, `COMBYTE`, `GETADR`, the floating point routines (`FADD`, `FSUB`, `FMULT`, `FDIV`, `MOVFM`, `MOVMF`, `FCOMP`, `FINT`, `FABS`, `FRND` etc.: `INT`, `ABS` and `RND` get an `F`, since some assemblers take those names to be their functions), `LINPRT`, `PRNTFAC`, and the hi-res routines (`HGR`, `HGR2`, `HCLR`, `BKGND`, `HPOSN`, `HPLOT0`, `HGLIN`, `HFIND`, `DRAW0`, `XDRAW0`, `HFNS`, `SETHCOL`). Their descriptive names start `basic_` or `hires_`, e.g. `basic_print_string` for `STROUT`. Their calls are commented as the Monitor's are, and some say more:

| Routine | Comment |
| ------- | ------- |
| `STROUT` | The string at A (low) and Y (high) is marked as a zero-terminated string (in high ASCII, or ASCII if its first byte has bit 7 clear), and A and Y are written as its label's low and high bytes: `lda #<message`, `ldy #>message` |
| `LINPRT` | `Print 4660` (A is the high byte, X the low) |
| `HPOSN`, `HPLOT0` | `Plot a hi-res point at (140, 96)` (X and Y are x's low and high bytes, A is y) |
| `HGLIN` | `Draw a hi-res line to (279, 191)` (A and X are x's low and high bytes, Y is y) |
| `SETHCOL` | `Set the hi-res colour to 3 (white)` |

Applesoft's zero page is named too, where the Monitor's names don't cover it: `LINNUM`, `TXTTAB`, `VARTAB`, `ARYTAB`, `STREND`, `FRETOP`, `MEMSIZ`, `CURLIN`, `DATPTR`, `VARPNT`, `FAC`, `ARG`, `TXTPTR`, `ERRFLG`, `ERRLIN`, `ERRNUM`, `HPAG`, `SCALE`, `SHAPEL`/`SHAPEH`, `ROT` and others, and `usr_jump` ($0A, the USR function's JMP). Code that sets the USR function's address, or the `&` command's, has its handler traced and named (`usr_handler`, `ampersand_handler`).

**Follows ProDOS 8's MLI calls.** A program calls ProDOS with `jsr $BF00` (`MLI`), followed by the call's number and the address of its parameter list, and ProDOS returns after them. So py8dis carries on tracing after them (except after QUIT, which doesn't return), names the number (`MLI_OPEN` etc., or `mli_open` with descriptive names), comments the call, and labels and marks the parameter list:

```
    jsr MLI                 ; ProDOS: open a file
    !byte MLI_OPEN
    !word open_params
    ...
open_params
    !byte 3                 ; Parameter count
    !word pathname          ; Pathname
    !word io_buffer         ; I/O buffer (1024 bytes)
open_ref
    !byte 0                 ; Reference number (returned)
...
pathname
    !byte data_buffer - l2084
l2084
    !text "PICTURE"
data_buffer
```

- **Parameter lists:** each is labelled after its call (`open_params`, `read_params`…, then `_2` etc.), unless it has a name, and marked as its call's parameters, each with a comment. If its count isn't the call's, only the count is marked.
- **Pointers:** a pathname's address is labelled `pathname` and marked as a length-prefixed string (in ASCII, or high ASCII if its first character has bit 7 set), a buffer's `data_buffer` or `io_buffer`, and an interrupt handler's `interrupt_handler` (traced).
- **Reference numbers** are labelled after the call (`open_ref`, `read_ref`…), since code copies the one OPEN returns into the lists of the calls that follow.
- **The calls:** all of ProDOS 8's: CREATE, DESTROY, RENAME, SET_FILE_INFO, GET_FILE_INFO, ON_LINE, SET_PREFIX, GET_PREFIX, OPEN, NEWLINE, READ, WRITE, CLOSE, FLUSH, SET_MARK, GET_MARK, SET_EOF, GET_EOF, SET_BUF, GET_BUF, ALLOC_INTERRUPT, DEALLOC_INTERRUPT, QUIT, READ_BLOCK, WRITE_BLOCK and GET_TIME (see `prodos_mli_calls` in `appletables.py`).

ProDOS's error codes are in `apple.prodos_errors`, for a control file to use (e.g. with `constant()` and `expr()`); they aren't found automatically.

**Names ProDOS's global page** ($BF00-$BFFF): `MLI`, `JSPARE`, `DATETIME`, `SYSERR`, `SYSDEATH`, `SERR`, `DEVADR`, `DEVNUM`, `DEVCNT`, `DEVLST`, `BITMAP`, `INTRUPT1` to `INTRUPT4`, the interrupt registers, `DATE`, `TIME`, `LEVEL`, `BUBIT`, `MACHID`, `SLTBYT`, `PFIXPTR`, `MLIACTV`, `CMDADR`, `SAVEX`, `SAVEY`, `IBAKVER`, `IVERSION`, `KBAKVER` and `KVERSION` (with descriptive names starting `prodos_`), under the heading `; ProDOS global page`.

**Groups the memory locations** in the output by region: zero page, the stack, the input buffer, page 3, the DOS vectors, the vectors, the text and lo-res pages, the hi-res pages, ProDOS's global page, the soft switches, the language card, the slots' I/O and ROMs, the expansion ROM, and the Applesoft and Monitor ROMs.

The tables are in `py8dis/appletables.py`, and a control file can use them as e.g. `apple.apple2_monitor_routines`. Apple's names were checked against the symbol files of Andy McFadden's [6502bench SourceGen](https://github.com/fadden/6502bench).

## Applesoft programs

`apple.applesoft_program(runtime_addr=0x0801)` marks the tokenised Applesoft program at the address ($0801, where Applesoft programs start, by default), after `apple.apple2()`:

```python
load_apple_file("HELLO#fc0801")
apple.apple2()
apple.applesoft_program()
```

Each line is labelled (`basic_line_10`), its link to the next line is written as that line's label, its line number is in decimal, and its keywords are bytes and its other text ASCII strings. A comment lists the line as LIST shows it, with a space either side of each keyword:

```
; 30 FOR I = 1 TO 3: CALL 2304: NEXT
basic_line_30
    !word basic_line_40
    !word 30
    !byte $81
    !text "I"
    ...
```

The address a CALL calls (which can be negative, e.g. `CALL -936`, $FC58) is traced if it's in the loaded data, and named `call_entry` (then `call_entry_2` etc.) unless it has a name. It returns the address after the program (after the two zeros that end it, labelled `basic_end`), or None if there isn't a valid program at the address. It isn't called by `apple.apple2()`, since a program at $0801 is often machine code.

