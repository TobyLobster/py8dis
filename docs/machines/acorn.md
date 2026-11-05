# Acorn: BBC Micro, B+, Master, Electron and Atom

For a program for one of Acorn's 6502 machines, add this after `load()`:

```python
from commands import *
import acorn

load(0x1900, "game.bin", "6502")
acorn.bbc()
entry(0x1900)
go()
```

Use `acorn.bbc()` for the BBC Micro, `acorn.b_plus()` for the B+, `acorn.master()` for the Master (load it with the CPU `"65C02"` if it uses the 65C02's instructions) and `acorn.electron()` for the Electron. For the Atom, see [below](#the-acorn-atom).

The output is for beebasm by default; for Baron, its successor, run the control file with `--baron` (see [assemblers.md](../assemblers.md#baron)). Any of the other 6502 assemblers works too.

## What it does

**Names the OS calls.** The MOS's entry points get their names, in capitals as in Acorn's documentation: `OSWRCH`, `OSBYTE`, `OSWORD`, `OSFILE`, `OSCLI`, `OSASCI`, `OSNEWL`, `OSRDCH`, `OSARGS`, `OSBGET`, `OSBPUT`, `OSGBPB`, `OSFIND`, `GSINIT`, `GSREAD` and the rest (with `OSWRSC` on the B+ and Master). `config.set_upper_case_os_calls(False)`, before `acorn.bbc()`, gives `oswrch` etc. Like all the machine names, they're only in the disassembly if the program uses them.

**Comments the OS calls.** Each call is commented with what it does, when the registers are known. The number in A is named, and the address of a parameter block in X and Y is written with its label:

```
    lda #osbyte_set_user_flag
    ldx #&22
    ldy #0
    jsr OSBYTE              ; Set user flag byte to 34
    lda #osword_read_clock
    ldx #<osword1block
    ldy #>osword1block
    jsr OSWORD              ; Read system clock
    lda #&41
    jsr OSWRCH              ; Write character 65
```

**Decodes VDU sequences.** The characters the code writes with OSWRCH are decoded as VDU commands, however A is set: e.g. `; Select mode 7` before `lda #22 : jsr OSWRCH : lda #7 : jsr OSWRCH`, or `; Position text cursor at (X,Y)`, `; PLOT 69,640,512`, `; Print "Hi"`. A run of calls can start part way through a sequence that earlier code started, so this is a best guess: py8dis takes the way of reading the characters that explains the most of them (zeros, as VDU 0 does nothing, count as more likely to be parameters), preferring fewer, longer commands.

**Names the OS vectors** (`userv`, `brkv`, `irq1v`, `wrchv` and so on, with `wrchv+1` for the high byte), and **follows the code that sets them**: the address stored is traced as code, named after the vector (e.g. `handle_wrchv`), and the code is commented, e.g. `; Set write character vector to 'handle_wrchv'`. This is found from the values stored, so it works in any order, with any registers, and with other instructions in between. A vector with only one byte set to a known value has a comment on that store, e.g. `; Set the low byte of IRQ 2 vector to &00`.

**Names the hardware**, in FRED, JIM and SHEILA (&FC00-&FEFF), e.g. `crtc_address_register`, `system_via_ier`, `system_via_register_b`, for the machine's own hardware. The CRTC register numbers stored to `crtc_address_register` are named too. &FC00-&FEFF is marked as I/O (see [`io_range()`](../commands.md#io_range)).

**Names some of the OS workspace** (`os_text_ptr`, `romsel_copy`, `osrdsc_ptr`), and groups the memory locations at the top of the disassembly by region (zero page, the stack, the OS vectors, the OS and language workspace, user memory, paged ROM, the MOS ROM, the hardware and the MOS entry points).

**Recognises some common pieces of code** (see [snippets](../snippets-and-hooks.md#snippets)), and comments them: a loop that prints a message (`; print message`), a loop that prints the same character several times (`; print character 32 repeatedly`), and tables of the screen address (or the offset from the start of the screen) of each character row.

## Sideways ROMs

`acorn.is_sideways_rom()`, for a paged ROM loaded at &8000, names its header (`rom_header`, the language and service entries and their handlers, `rom_type`, `copyright_offset`, `binary_version`, `title`, `version` and `copyright`), marks its strings, and traces the code the entries jump to.

```python
load(0x8000, "dfs226.rom", "6502")
acorn.bbc()
acorn.is_sideways_rom()
go()
```

## The OS's numbers, for your own use

The tables py8dis uses for the comments are there for a control file to use too, e.g. with `expr()` or `constant()`: `acorn.inkey_enum` (the INKEY numbers of the keys), `acorn.osbyte_enum`, `acorn.osword_enum`, `acorn.osfile_enum`, `acorn.osfind_enum`, `acorn.osgbpb_enum`, `acorn.buffer_enum`, `acorn.event_enum`, `acorn.baud_rate_enum` and `acorn.crtc_registers_enum`. Each is a dictionary from the number to its name:

```python
expr(0x2101, acorn.inkey_enum)       # lda #inkey_key_space, rather than lda #&9d
```

`acorn.os_call_name("osbyte")` gives an OS call's name in the case chosen with `config.set_upper_case_os_calls()`.

See `examples/python/acorn_os_calls.py`, `acorn_vdu.py` and `acorn_vectors.py` for small examples, and `planb.py`, `dfs226.py` and `anfs418.py` for real programs.

## The Acorn Atom

For a program for the Acorn Atom, use `acorn.atom()` after `load()`:

```python
from commands import *
import acorn

load(0x2900, "game.bin", "6502")
acorn.atom()
entry(0x2900)
go()
```

An ATM file (the format of the Atom's emulators and AtoMMC) can be loaded with [`load_atm()`](../commands.md#load_atm), which reads its load and execution addresses from its header, and makes the output assemble to the whole file:

```python
start = load_atm("game.atm")
acorn.atom()
```

The Atom's operating system is a different design from the BBC Micro's MOS (it has no OSBYTE or OSWORD, and its own entry points, vectors and hardware), so `acorn.atom()` sets up its own names and comments:

**Names the OS calls**, in capitals as in Acorn's *Atomic Theory and Practice*: `OSSHUT`, `OSFIND`, `OSBPUT`, `OSBGET`, `OSSTAR`, `OSRDAR`, `OSSAVE`, `OSLOAD`, `OSRDCH`, `OSECHO`, `OSASCI`, `OSCRLF`, `OSWRCH` and `OSCLI` (#FFCB-#FFF7). `config.set_upper_case_os_calls(False)`, before `acorn.atom()`, gives `oswrch` etc.

**Comments the OS calls**, e.g. `; Write character 65`, `; Open file for input (C=1)` (with the carry, if it's known), `; Close all files (Y=0)` or `; Load a file`, and where the registers they use are set (e.g. `; Y=file handle`, `; X=zero page address of the load parameter block`) and where what they return is used (`; A=character read`).

**Comments what's written with OSWRCH**, OSASCI and OSCRLF, however A is set: runs of printable characters (`; Print "HELLO"`), and the control codes OSWRCH acts on, e.g. `; Clear the screen` (12), `; Page mode on` (14), `; Sound the bell` (7), `; Stop screen output` (21), with CR and LF together (or OSASCI's CR) as `; Start a new line`.

**Names the kernel routines** that programs call, and comments the calls with what they do: `print_inline_string` (#F7D1), `print_hex` (#F802), `print_hex_space`, `print_hex_2_bytes`, `print_hex_4_bytes`, `print_space`, `wait_for_flyback` (#FE66), `wait_for_flyback_or_now` and `scan_keyboard` (#FE71), and the kernel's own handlers that the vectors point to by default, e.g. `kernel_wrch` (#FE52, as in `jmp kernel_wrch` at the end of a replacement OSWRCH). After a call to #F7D1, the string it prints is marked, and tracing carries on at the first byte with bit 7 set, where the kernel continues:

```
    jsr print_inline_string     ; Print the string after the JSR, up to a byte with bit 7 set, and carry on there
    equs "HELLO ATOM"
    nop
```

**Names the vectors** at #0200-#021F (`nmivec`, `brkvec`, `irqvec`, `comvec`, `wrcvec`, `rdcvec`, `lodvec`, `savvec`, `rdrvec`, `strvec`, `bgtvec`, `bptvec`, `fndvec`, `shtvec`, and Econet's `in1vec` and `in2vec`), and **follows the code that sets them**, as for the BBC Micro: the handler is traced and named (e.g. `handle_wrcvec`), and the code is commented, e.g. `; Set write character vector to 'handle_wrcvec'`.

**Names the hardware**: the 8255 PPI at #B000-#B003 (`ppi_port_a`, the keyboard row and the 6847's mode; `ppi_port_b`, the keyboard columns; `ppi_port_c`, the tape, speaker and sync; `ppi_control`), the VIA at #B800 (`via_register_a` etc., as on the BBC Micro) and the ROM latch at #BFFF (`rom_latch`). #B000-#BFFF is marked as I/O.

**Comments what's written to the 8255**, when the value is known (or after `lda port`, then `ora #n`, `and #n` and `eor #n`, which set, clear and toggle bits):

```
    lda #&f0
    sta ppi_port_a              ; Select graphics mode 4 (256x192, 2 colours)
    lda ppi_port_a
    and #&f0
    ora #3
    sta ppi_port_a              ; Select keyboard row 3
    lda ppi_port_c
    eor #4
    sta ppi_port_c              ; Toggle the speaker
    lda #5
    sta ppi_control             ; Set port C bit 2 (speaker high)
```

For #B000, that's the 6847's mode in bits 4-7 (text mode, CLEAR 1-4's 2-colour graphics modes, or the 4-colour ones, e.g. `Select 64x64 graphics, 4 colours`) and the keyboard row in bits 0-3. For #B002 (port C), it's the tape output, the 2.4 kHz tape tone, the speaker and the colour set (bit 3, `Select colour set 1`). For #B003, it's the bit of port C set or cleared, or the 8255's modes.

It **comments tests of the inputs** too:
- `bit ppi_port_c` before `bpl` or `bmi` is `Test the field sync`, and before `bvc` or `bvs`, `Test the REPT key`.
- For #B001, the same are `Test the SHIFT key` and `Test the CTRL key`.
- Before `beq` or `bne`, the comment names the bits in A, if A is known (e.g. `Test the 2.4 kHz tape tone input`).
- With no branch after it, it names both bits 7 and 6.
- `lda ppi_port_b : and #&40` is `Test the CTRL key`, and the same for the other input bits (#B001's bits 0-5 are the keyboard row's columns).

**Names some of the workspace**: the OS's (`screen_line_address`, `cursor_column`, `cursor_mask`, `page_mode_count`, `lock_flag`, `nomon_flag`, `printer_ignore_char`, `irq_save_a`, `input_buffer` at #0100, `string_buffer` at #0140 and `plot_vector` at #03FE) and BASIC's (`basic_error_number`, `basic_line_number`, `rnd_seed`, `basic_error_handler` and `text_space_page`), and groups the memory locations at the top of the disassembly by region (zero page, the input and string buffers, the stack, the OS vectors, the workspace, extension and user memory, the screen, the utility, BASIC, floating point, DOS and kernel ROMs, the I/O and the OS entry points).

**Recognises loops that print** a message, or the same character several times, with OSWRCH, as for the BBC Micro.

### Atom BASIC programs

`acorn.atom_basic_program(runtime_addr=0x2900)`

Marks the Atom BASIC program at `runtime_addr`, by default #2900, where BASIC's text space starts. Atom BASIC isn't tokenised: a program is a CR, then each line's number (high byte first), its text and a CR, ending with #FF. The CR at the start is labelled `basic_start`, and each line is labelled (`basic_line_10`), with its number as two bytes, its text as a string and its CR, and listed in a comment. The #FF at the end is labelled `basic_end`:

```
; 20 P."HELLO, WORLD"
.basic_line_20
    equb 0, 20
    equs "P.", '"', "HELLO, WORLD", '"'
    equb &0d
```

An address that a LINK calls (`LINK #2950`, or in decimal), in the loaded data, is traced as code, and named `link_entry` (then `link_entry_2` etc.) unless it already has a name. It returns the address after the program, or None if there isn't a valid program there. For a program saved as an ATM file (whose execution address is BASIC's, #C2B2):

```python
load_atm("game.atm")
acorn.atom()
acorn.atom_basic_program()
go()
```

### The Atom's kernel ROM

`examples/python/atom_kernel.py` disassembles the Atom's kernel ROM (its OS, and the BASIC statements and COS commands it adds), loaded at #F000, with `acorn.atom()`, as a larger example. It traces the code from:
- the 6502's vectors;
- the default vectors the kernel copies to #0204 on reset;
- its two command tables (the BASIC statements PLOT, DRAW, MOVE, CLEAR, DIM, `[`, OLD and WAIT at #F000, and the * commands at #F8BE, each entry a name and then the routine's address, high byte first);
- the plot routine for each graphics mode;
- the tables of OSWRCH's control code handlers and OSRDCH's key handlers (the low bytes of their addresses);
- the routines BASIC calls.

It classifies and names the tables, and names every OS entry point and kernel routine, whether it's used or not.

### The Atom's BASIC ROM

`examples/python/atom_basic_rom.py` disassembles the Atom's BASIC ROM, loaded at #C000, with `acorn.atom()`. Atom BASIC isn't tokenised: it finds each keyword in the program's text as it runs it, with two matchers, which it calls with a starting index in X (`ldx #n : jmp #C233`, or `jmp #C27B` for single characters). The control file finds those calls, then decodes the matchers' tables, to trace every routine they give and name it after its keyword (e.g. `statement_print`, `function_rnd`, `op_add`), and marks the tables as text and the routines' high and low bytes. It also traces and names the routines the kernel calls, and the BASIC ROM's calls to the floating point ROM's handlers (through #D002 and #D004), and marks its other data: the powers of ten for printing numbers, and its default error handler, which is a line of BASIC.

The tables are in `acornatom` (e.g. `acornatom.atom_vectors`, `acornatom.atom_control_codes`). See `examples/python/atom_test.py`.
