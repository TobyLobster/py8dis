# Apple II

For a program for the Apple II+, IIe, enhanced IIe or IIc, use `apple.apple2()` after loading it:

```python
from commands import *
import apple

start = load_apple_file("GAME#062000")
apple.apple2()
entry(start)
go()
```

Apple II files are loaded with [`load_apple_file()`](../commands.md#load_apple_file) (an AppleSingle file, as cc65 makes, or a file whose name gives its type and address, as CiderPress names them), [`load_dos33_binary()`](../commands.md#load_dos33_binary) (a DOS 3.3 binary file with its 4-byte header), or `load()`.

The output is for beebasm by default; for Merlin 32, in the syntax of Merlin, the Apple II's best-known assembler, run the control file with `--merlin32` (see [assemblers.md](../assemblers.md#merlin-32)). ca65, acme and 64tass, also used for the Apple II, and the other 6502 assemblers work too.

`apple.apple2(model="ii+", names="apple")` takes:

- `model`:
  - `"ii+"` (the default);
  - `"iie"` for the unenhanced IIe, which adds the IIe's status switches, its memory switches and its 80-column firmware's `AUXMOVE` and `XFER`;
  - `"iie-enhanced"` for the enhanced IIe: the same, with a 65C02, and MouseText in its alternate character set;
  - `"iic"` for the IIc, also with a 65C02, whose own switches replace those of the IIe's it lacks or differs in (see [The IIc](#the-iic)).

  The II+ and the unenhanced IIe have a 6502: load the program with `"6502"` (or `"6510"` for one with the undocumented opcodes). The enhanced IIe and the IIc have a 65C02, which runs 6502 programs too: load it with `"65C02"` or `"6502"` (but not `"6510"`, since the 65C02 doesn't run the undocumented opcodes).
- `names`: `"apple"` (the default) for Apple's names, as in its reference manuals, in capitals: `COUT`, `HOME`, `CH`, `CSWL`, `KBD`, `TXTCLR`. `config.set_upper_case_os_calls(False)`, before `apple.apple2()`, gives them in lower case. `"descriptive"` gives py8dis's own names instead: `print_char`, `clear_screen`, `cursor_column`, `output_hook`, `keyboard`, `show_graphics`.

## What it does

**Makes high ASCII the text encoding.** The Apple II's ROM, keyboard and screen use ASCII with bit 7 set, so `apple.apple2()` makes it the session's text encoding (see [text-encodings.md](../text-encodings.md)): strings like `$C8 $C5 $CC $CC $CF` are text ("HELLO"), and so is the hex dump.

**Names the Monitor's routines**, if the program uses them: `PLOT`, `HLINE`, `VLINE`, `CLRSCR`, `SETCOL`, `SCRN`, `PRNTAX`, `PRBL2`, `PREAD`, `INIT`, `SETTXT`, `SETGR`, `SETWND`, `TABV`, `SETPWRC`, `BASCALC`, `BELL1`, `VIDOUT`, `VTAB`, `VTABZ`, `CLREOP`, `HOME`, `CR`, `LF`, `SCROLL`, `CLREOL`, `WAIT`, `NXTA1`, `RDKEY`, `KEYIN`, `RDCHAR`, `GETLN`, `GETLN1`, `CROUT`, `PRBYTE`, `PRHEX`, `COUT`, `COUT1`, `MOVE`, `SETINV`, `SETNORM`, `SETKBD`, `INPORT`, `SETVID`, `OUTPORT`, `BELL`, `SAVE`, `RESTORE`, `IORTS`, `MON`, `MONZ` and others (see `apple2_monitor_routines` in `py8dis/appletables.py`). On the IIe, enhanced IIe and IIc, `AUXMOVE` ($C311) and `XFER` ($C314) too. The ROM's ID bytes, which programs read to tell the models apart, are `VERSION` ($FBB3), `ZIDBYTE` ($FBC0) and `iic_rom_version` ($FBBF, the IIc's ROM version).

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

A character printed with `COUT` is written as one where it's loaded: `lda #'A' | $80` (as the assembler writes a high ASCII character literal; Merlin 32's is `lda #"A"`).

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
- A read of an input: `Test button 0 (bit 7 set if it's pressed)` (on the IIe, `Test the Open Apple key`), `Test paddle 0's timer (bit 7 set until it runs out)`, and on the IIe `Test whether 80 columns are shown (bit 7)` etc. A loop reading `KBD` until bit 7 is set is `Wait for a key`, and on the IIe and enhanced IIe, one reading `RDVBLBAR` is `Wait for the vertical blank` or `Wait for the vertical blank to end`.

For a 65C02, its `STZ`, `TSB` and `TRB` count as accesses too (e.g. `stz SET80VID ; Show 80 columns`).

**Names the IIe's switches at $C000-$C00F where they're written.** Reading these addresses reads the keyboard, but writing them sets the IIe's memory and display switches, so each write gets the switch's name, with a comment, while reads keep `KBD`:

```
    sta SET80VID            ; Show 80 columns
    sta SET80STORE          ; Use page 2 for auxiliary memory (80STORE on)
    sta WRCARDRAM           ; Write auxiliary memory ($0200-$BFFF)
```

The names are `CLR80STORE`, `SET80STORE`, `RDMAINRAM`, `RDCARDRAM`, `WRMAINRAM`, `WRCARDRAM`, `SETSLOTCXROM`, `SETINTCXROM`, `SETSTDZP`, `SETALTZP`, `SETINTC3ROM`, `SETSLOTC3ROM`, `CLR80VID`, `SET80VID`, `CLRALTCHAR` and `SETALTCHAR` (with descriptive names such as `store_80_on`, `write_aux_ram` and `show_80_columns`). (The newer manuals call the first `80STOREOFF` and so on, which can't be a label, since it starts with a digit.) `SETALTCHAR`'s comment says what the alternate character set has: inverse lower case instead of flashing characters, and on the enhanced IIe and the IIc, MouseText too.

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

**Names DOS 3.3's entry points** in page 3, and comments their calls. Apple didn't name them, so their names are descriptive in both styles:

| Address | Name | Comment |
| ------- | ---- | ------- |
| $03D0 | `dos_warm_start` | `Go to DOS's warm start (BASIC, keeping its program)` |
| $03D3 | `dos_cold_start` | `Go to DOS's cold start (BASIC, clearing its program)` |
| $03D6 | `dos_file_manager` | `Call DOS's file manager (creating the file if it isn't found)` for X=0, or `(not creating the file if it isn't found)` |
| $03D9 | `dos_rwts` | `Call RWTS (DOS's read/write track/sector routine)` |
| $03DC | `dos_get_fm_params` | `Find the file manager's parameter list` (and `Y=parameter list's address (low byte)` where Y is used) |
| $03E3 | `dos_get_iob` | `Find DOS's IOB (RWTS's parameters)` |
| $03EA | `dos_connect_hooks` | `Reconnect DOS to the input and output hooks (KSW and CSW)` |

RWTS is also called at $B7B5 (`dos_rwts_entry`, which disables interrupts first) and $BD00 (`RWTS`, as DOS's source names it). Tracing stops after a JSR to DOS's warm or cold start, which don't return.

**Marks the IOBs that RWTS is called with.** RWTS takes the address of its IOB (input/output block) in Y (low byte) and A (high byte). Where they're loaded with it, they're written as its label, `rwts_iob` (then `rwts_iob_2` etc., unless it has a name), and the IOB is marked, each field with a comment:

```
    lda #17
    sta rwts_iob_track
    ...
    lda #>rwts_iob
    ldy #<rwts_iob
    jsr dos_rwts            ; Call RWTS (DOS's read/write track/sector routine)
    ...
rwts_iob
    !byte 1                 ; Table type (1)
    !byte $60               ; Slot times 16
    !byte 1                 ; Drive (1 or 2)
    !byte 0                 ; Volume expected (0 for any)
rwts_iob_track
    !byte 0                 ; Track
    ...
    !word rwts_dct          ; Device characteristics table
    !word sector_buffer     ; Sector buffer (256 bytes)
    !byte 0                 ; Not used
    !byte 0                 ; Byte count for a partial sector (0 for 256)
    !byte 1                 ; Command (0 seek, 1 read, 2 write, 4 format)
    ...
```

- **Fields:** each gets a name from the IOB's (`rwts_iob_slot`, `rwts_iob_track`, `rwts_iob_sector`, `rwts_iob_buffer`, `rwts_iob_command`, `rwts_iob_error` and so on), used where the code refers to it, as code usually sets the track, sector and command before each call.
- **Pointers:** the device characteristics table's address is labelled `rwts_dct` and the table marked (device type, phases per track, motor on time), and the sector buffer's is labelled `sector_buffer`, unless they have names (e.g. DOS's own table, `DCT`).
- **DOS's own IOB**, as `lda #$b7 : ldy #$e8` loads it, is written as `IOB`. Where Y and A come from `dos_get_iob` instead, they're commented (`Y=IOB's address (low byte)`).

The file manager's parameter list is always DOS's own, so it isn't marked: code finds it with `dos_get_fm_params` and fills it in through a pointer. The file manager's calls and return codes, and RWTS's error codes, are in `apple.dos33_file_manager_calls`, `apple.dos33_file_manager_errors` and `apple.dos33_rwts_errors`, for a control file to use.

**Names DOS 3.3's memory**, where it is in a 48K machine:

- **DOS's IOB**, with the names DOS's source gives its fields: `IOB` ($B7E8), `IBSLOT`, `IBDRVN`, `IBVOL`, `IBTRK`, `IBSECT`, `IBDCTP`, `IBBUFP`, `IBCMD`, `IBSTAT`, `IBSMOD`, `IBPSLT` and `IBPDRV` (descriptive: `dos_iob`, `dos_iob_slot` etc.), and its device characteristics table, `DCT` ($B7FB);
- with descriptive names in both styles: the length and address of the file last loaded, as BLOAD sets them (`dos_load_length` $AA60, `dos_load_address` $AA72); the output and input hooks DOS passes characters on to (`dos_saved_output_hook`, `dos_saved_input_hook`); MAXFILES (`dos_maxfiles`); which BASIC is active (`dos_basic_flag`); the file manager's parameter list (`dos_fm_params`); the VTOC and directory sector buffers (`dos_vtoc_buffer`, `dos_directory_buffer`); and the address of the first file buffer (`dos_buffer_chain`).

DOS commands that a program prints with COUT, after a Ctrl-D, are commented as described above (`DOS command: BLOAD GAME`).

**Names the slots' ROMs where programs call them.** A program starts a card's firmware by calling $Cn00 for slot n, as PR#n does, so $C100-$C700 are named `slot_1_entry` to `slot_7_entry`, with comments: `jsr slot_3_entry ; Start the 80-column firmware (as PR#3 does)` (on the IIe, enhanced IIe and IIc), `jmp slot_6_entry ; Start slot 6's firmware (as PR#6 does: for a disk, boot it)`, and `Start slot 1's firmware (as PR#1 does)` and so on for the others. For a card's ROM itself, see [Slot firmware](#slot-firmware).

**Leaves the program's own memory alone.** ProDOS's and DOS's names and hooks (and the slots' entry points) are only used for addresses where nothing is loaded. A program loaded where ProDOS or DOS would be isn't using them there (Penetrator, for one, runs from $4000 to $B921), and its own addresses mustn't get their names.

**Groups the memory locations** in the output by region: zero page, the stack, the input buffer, page 3, the DOS vectors, the vectors, the text and lo-res pages, the hi-res pages, ProDOS's global page, the soft switches, the language card, the slots' I/O and ROMs, the expansion ROM, and the Applesoft and Monitor ROMs.

The tables are in `py8dis/appletables.py`, and a control file can use them as e.g. `apple.apple2_monitor_routines`. Apple's names were checked against the symbol files of Andy McFadden's [6502bench SourceGen](https://github.com/fadden/6502bench).

## The IIc

The IIc has the IIe's memory and display switches, but no slots, cassette or annunciators, and an IOU that handles the mouse and the vertical blank's interrupt. So with `model="iic"`, its own switches replace those of the IIe's it lacks or differs in:

| Address | Name | Comment |
| ------- | ---- | ------- |
| $C015, $C017 | `MOUXINT`, `MOUYINT` | `Test for a mouse X interrupt (bit 7 set if there was one)` |
| $C019 | `VBLINT` | `Test for a vertical blank interrupt (bit 7 set if there was one)`, or in a loop, `Wait for the vertical blank interrupt` |
| $C048 | `MOUCLR` | `Clear the mouse's interrupts` |
| $C058, $C059 | `MOUDSBL`, `MOUENBL` | `Disable the mouse's interrupts (with IOUDIS off)` |
| $C05A, $C05B | `DISVBL`, `ENVBL` | `Enable the vertical blank interrupt (with IOUDIS off)` |
| $C05E, $C05F | `DHIRESON`, `DHIRESOFF` | `Turn double hi-res on (with IOUDIS on)` |
| $C060 | `column_switch` | `Test the 40/80-column switch (bit 7)` |
| $C063 | `MOUBUT` | `Test the mouse's button (bit 7)` |
| $C066, $C067 | `MOUX1`, `MOUY1` | `Test the mouse's X1 signal (bit 7, its direction)` |
| $C070 | `PTRIG` | `Start the paddles' timers, and clear the vertical blank interrupt` |
| $C07E, $C07F (read) | `RDIOUDIS`, `RDDHIRES` | `Test whether IOUDIS is on (bit 7)` |
| $C07E, $C07F (written) | `IOUDISON`, `IOUDISOFF` | `IOUDIS on: disable the IOU's switches ($C058-$C05D), enable double hi-res's` |
| $C078, $C079 (written) | `IOUDSBL`, `IOUENBL` | the same as $C07E and $C07F (the addresses the IIc's firmware uses) |
| $C098-$C09B, $C0A8-$C0AB | `serial_1_data`, `serial_1_status`, `serial_1_command`, `serial_1_control`, and `serial_2_...` | (the serial ports' 6551s) |

The names are from the IIc's firmware source as Apple published it (`MOUXINT`, `VBLINT`, `MOUBUT`, `IOUDSBL`...) and Apple's IIc Technical Notes (`ENVBL`, `RDIOUDIS`); `DISVBL`, `DHIRESON`, `IOUDISON` and `RDDHIRES` are the names in common use (A2osX, cc65's `apple2.inc`, SourceGen) for switches those don't name, and the others are descriptive in both styles. IOUDIS's switches act when written, so, like the IIe's at $C000-$C00F, they're named where they're written. The IIe's switches the IIc doesn't have (`TAPEOUT`, annunciator 2, whose addresses are the IOU's mouse edge switches, `SETSLOTCXROM`, `SETINTCXROM`, `SETINTC3ROM` and `SETSLOTC3ROM`) aren't named.

The enhanced IIe has the IIe's switches.

## Slot firmware

`apple.slot_rom(slot)` sets up for a card's ROM, loaded at $Cn00 for slot n (1 to 7), after `apple.apple2()`:

```python
load(0xc700, "CARD.ROM", "6502")
apple.apple2()
apple.slot_rom(7)
go()
```

- **The entry point** at $Cn00, where PR#n, IN#n and booting from slot n start, is traced and labelled `slot_7_entry`.
- **A ProDOS block device** has $20, $00 and $03 at $Cn01, $Cn03 and $Cn05 (from the ProDOS 8 Technical Reference); $Cn07 is $3C if the Autostart ROM boots it (a Disk II's ID byte), or $00 for SmartPort. A comment says which. $CnFF is the low byte of its ProDOS driver's address ($00 and $FF mean a Disk II, which ProDOS drives itself):
  - the driver is traced and labelled `prodos_driver`, and $CnFF written as its low byte;
  - $CnFC-$CnFD, the number of blocks (0 to read it with STATUS), and $CnFE, the status byte, are marked and commented: `Status: 3 volumes; removable, formats, writes, reads, gives its status`;
  - ProDOS's parameters in zero page get their names in the ROM, instead of the Monitor's (`A4L` etc.): `driver_command` ($42), `driver_unit`, `driver_buffer` and `driver_buffer_high` ($44-$45), and `driver_block` and `driver_block_high` ($46-$47), under the heading `; ProDOS driver's parameters`;
  - for SmartPort, the dispatcher (3 bytes after the driver) is traced and labelled `smartport`, and calls to it in the ROM are decoded (see [SmartPort calls](#smartport-calls)).
- **A Pascal 1.1 card** has $38, $18 and $01 at $Cn05, $Cn07 and $Cn0B (from Apple's Technical Note Miscellaneous #8):
  - BASIC's input and output entry points at $Cn05 and $Cn07 (whose SEC and CLC are the ID bytes $38 and $18) are traced and labelled `basic_input` and `basic_output`;
  - the device signature at $Cn0C is commented with its class and ID: `Device signature: class 3 (serial or communications), ID 1` (for the classes of Apple's own cards: the mouse, the serial ports and the 80-column firmware; other classes are given by number);
  - the offsets of the INIT, READ, WRITE and STATUS routines at $Cn0D-$Cn10 are written as their labels' low bytes, and the routines traced and labelled `pascal_init`, `pascal_read`, `pascal_write` and `pascal_status`;
  - for the mouse (device signature $20), the offsets of its routines at $Cn12-$Cn19 too: `SETMOUSE`, `SERVEMOUSE`, `READMOUSE`, `CLEARMOUSE`, `POSMOUSE`, `CLAMPMOUSE`, `HOMEMOUSE` and `INITMOUSE` (descriptive: `mouse_set_mode`, `mouse_serve` etc.).
- **The card's I/O,** $C080 + 16n to $C08F + 16n, is named for the slot: `sta slot_7_io+7`. In the ROM of a card that isn't a Disk II, its accesses to $C080-$C08F indexed by the slot times 16 are the card's own (`lda card_io_14,x`, under the heading `; The card's I/O (indexed by the slot times 16)`), not the Disk II's names that `apple.apple2()` gives them elsewhere.
- **`MSLOT`** ($07F8), where a card notes that it's using the expansion ROM ($C800-$CFFF), is named.

Here's the start of [Apple2-IO-RPi](https://github.com/tjboldt/Apple2-IO-RPi)'s drive firmware for slot 7, with the names from its source:

```
; Slot 7's ROM: PR#7, IN#7 and booting from slot 7 start here
; ID bytes $20, $00 and $03 at $c701, $c703 and $c705: a ProDOS block device, which the
; Autostart ROM boots ($3C at $c707, as a Disk II's)
slot_7_entry
    cpx #$20
    ...
Start
    ldx #$70
    stx BAS2H
    stx driver_unit
    lda #1
    sta driver_command
    ...
    !word 0                 ; Number of blocks (0: read it with STATUS)
    !byte $17               ; Status: 1 volume; writes, reads, gives its status
    !byte <DriverEntry      ; The low byte of the driver's address
```

Names given more than once (for several slots in one session) get `_2` etc., and names the control file gives are kept. It stops with an error if `apple.apple2()` hasn't been called, the slot isn't 1 to 7, or nothing is loaded at $Cn00. Not done: the optional Pascal routines some cards have after $Cn10, and finding entry points through other tables.

## SmartPort calls

SmartPort is called as ProDOS's MLI is: a JSR to its dispatcher is followed by the call's number and the address of its parameter list, and it returns after them. A program finds the dispatcher in a slot's ROM as it runs (at $Cn00 plus the byte at $CnFF, plus 3), so it usually calls it through a JMP of its own, whose address it sets. `apple.smartport_calls(addr)`, after `apple.apple2()`, says that a JSR to `addr` is a SmartPort call:

```python
apple.apple2(model="iie")
apple.smartport_calls(0x085b)
```

Each call is then decoded as the MLI's are (see above): tracing carries on after it, the number is named (`SP_READBLOCK` etc., or `smartport_readblock` with descriptive names), the call is commented, and the parameter list is labelled (`sp_readblock_params`) and marked, with its buffers labelled `data_buffer`, `status_list` and `control_list`:

```
    jsr smartport           ; SmartPort: read a block
    !byte SP_READBLOCK
    !word sp_readblock_params
    ...
sp_readblock_params
    !byte 3                 ; Parameter count
    !byte 1                 ; Unit number
    !word data_buffer       ; Data buffer (512 bytes)
    !byte 0, 0, 0           ; Block number
```

The calls are STATUS, READBLOCK, WRITEBLOCK, FORMAT, CONTROL, INIT, OPEN, CLOSE, READ and WRITE (see `smartport_calls_table` in `appletables.py`). Another number (a device's own call) is commented with its number. The extended calls ($40 and up, with longer addresses) aren't decoded, and tracing stops after them. `apple.slot_rom()` does this for a SmartPort device's own dispatcher.

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

