# Acorn: BBC Micro, B+, Master and Electron

For a program for one of Acorn's 6502 machines, add this after `load()`:

```python
from commands import *
import acorn

load(0x1900, "game.bin", "6502")
acorn.bbc()
entry(0x1900)
go()
```

Use `acorn.bbc()` for the BBC Micro, `acorn.b_plus()` for the B+, `acorn.master()` for the Master (load it with the CPU `"65C02"` if it uses the 65C02's instructions) and `acorn.electron()` for the Electron.

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
