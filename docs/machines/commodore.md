# Commodore: C64, VIC-20, C128, Plus/4, PET and 1541

For a Commodore program, add the machine's set-up after loading it:

```python
from commands import *
import commodore

start = load_prg("game.prg", "6510")
commodore.c64()
go()
```

| Machine                         | Set-up |
| ------------------------------- | ------ |
| Commodore 64                    | `commodore.c64(names="descriptive", rom_labels=True)` |
| VIC-20                          | `commodore.vic20(expansion=None, names="descriptive", rom_labels=True)` |
| C128 (in C128 mode)             | `commodore.c128(names="descriptive", rom_labels=True)` |
| Plus/4, C16 and C116            | `commodore.plus4(names="descriptive", rom_labels=True)` |
| PET, CBM 3000, 4000 and 8000    | `commodore.pet(basic=4, columns=40, names="descriptive", rom_labels=True)` |
| 1541 disk drive                 | `commodore.drive1541(rom="1541", names="descriptive", rom_labels=True)` |

(A C128 program in C64 mode is a C64 program: use `c64()`.) Load the program with the CPU `"6510"` if it uses the 6502's undocumented opcodes (see [cpus.md](../cpus.md)), or `"6502"`.

- [What it does (the C64)](#what-it-does-the-c64)
- [The C64's memory configuration](#the-c64s-memory-configuration)
- [Names](#names)
- [VIC-20](#vic-20)
- [C128](#c128)
- [Plus/4](#plus4)
- [PET](#pet)
- [1541 disk drive](#1541-disk-drive)
- [BASIC programs](#basic-programs)
- [Cartridges and ROMs](#cartridges-and-roms)

## What it does (the C64)

**Names the memory locations**, if the program uses them: zero page, the OS and BASIC workspace, the Kernal's and BASIC's vectors, the screen and sprite pointers, the VIC-II, the SID, the colour RAM, the CIAs and the 6510's I/O port. They're grouped under headings by region, e.g. `; VIC-II ($d000-$d3ff)`. The names are descriptive by default, e.g. `vic_border_colour`, `cia1_port_a`, `keyboard_buffer_length`; `commodore.c64(names="commodore")` uses the names in Commodore's documentation instead (the Programmer's Reference Guide and Commodore's source, and for the I/O registers *Mapping the Commodore 64*), e.g. `EXTCOL`, `CIAPRA`, `NDX`.

**Names the Kernal's jump table**, by Commodore's names (e.g. `CHROUT`, `SETLFS`), and comments each call and where its registers are set and used:

```
    lda #$0f              ; A=logical file number
    ldx #device_disk_8    ; X=device number
    ldy #$0f              ; Y=secondary address
    jsr SETLFS            ; Set logical file 15 to device 8 (disk drive), secondary address 15
    lda #2                ; A=filename length
    ldx #<filename        ; X=filename address (low byte)
    ldy #>filename        ; Y=filename address (high byte)
    jsr SETNAM            ; Set the filename to "i0"
```

Some calls get more:

- CHROUT's comment names the character (`Output $93 (clear screen)`), and a printable character is written as one where it's loaded (`lda #'a'`, with acme; see [text-encodings.md](../text-encodings.md));
- PLOT's and MEMTOP's comments say whether the call reads or sets (from the carry flag);
- SETNAM's filename, and the string printed by BASIC's STROUT, are marked as PETSCII strings;
- SAVE's zero page pointer is named.

**Names the ROMs' routines** that programs call (e.g. `jmp kernal_irq_handler` for $ea31, `basic_print_string` for STROUT), and all the labels in Commodore's source for the Kernal and BASIC ROMs. A program that replaces the ROMs should use `commodore.c64(rom_labels=False)`. Where a Kernal label in Commodore's source has the same name as a jump table entry or another name (e.g. PLOT, the routine at $e50a that `PLOT` at $fff0 jumps to), it has `_ROM` added (`PLOT_ROM`), and a BASIC label with the same name as another has `_BASIC` added (e.g. `STOP_BASIC`, BASIC's STOP command).

**Names colours** stored in the VIC-II's colour registers or the text colour, as constants: `lda #colour_black : sta vic_border_colour`.

**Comments the VIC-II's interrupts.** A store of a known value to its raster line register is commented with the line, e.g. `lda #100 : sta vic_raster_line ; Raster interrupt at line 100`. Bit 8 of the line is bit 7 of `vic_control_1` ($d011): it's included when a store to that, in the same run of code, sets it to a known value, or just after `and #n` or `ora #n` sets or clears that bit; otherwise the comment gives both lines (`Raster interrupt at line 100 (or 356, if bit 7 of $d011 is set)`). Stores to its interrupt enable and status registers are commented too (`Enable only the VIC-II's raster interrupt`, `Acknowledge the VIC-II's raster interrupt`), as is the usual `asl vic_interrupt_status` (`Acknowledge the VIC-II's interrupts`). The same is done for the C128 (but not where its MMU maps the I/O out).

**Follows the vectors set by the program**, e.g. `lda #<x : sta $0314 : lda #>x : sta $0315`. This is found from the values stored, so it works in any order, with any registers, and with other instructions in between (see [snippets](../snippets-and-hooks.md#effect-patterns)). The address is traced as code and named after the vector, e.g. `irq_handler` (or `irq_handler_2` etc. for more), with a comment, `; Set the IRQ vector to irq_handler`. A vector with only one byte set to a known value has a comment on that store, e.g. `; Set the high byte of the NMI vector to $00`.

**Lists the BASIC program** at $0801, if there is one (see [BASIC programs](#basic-programs)).

**Uses PETSCII** as the text encoding (see [text-encodings.md](../text-encodings.md)). Call `c64()` before marking any strings.

**Follows the memory configuration** the program sets with the 6510's port at $01 (see [below](#the-c64s-memory-configuration)).

## The C64's memory configuration

Many C64 programs switch the BASIC and Kernal ROMs, and the I/O, out of the memory map, to use the RAM underneath, by writing to the 6510's port at $01. `c64()` follows this through the code, much as `c128()` follows the C128's MMU:

- **The code that sets it is commented** with the configuration, when its value is known: e.g. `lda #$35 : sta cpu_port ; Set the memory configuration to RAM, I/O ($35)`. An `inc $01` or `dec $01`, or `lda $01` with immediate ANDs, ORAs and EORs then `sta $01` (e.g. `lda $01 : and #$f8 : ora #$05 : sta $01`), is commented too, where the configuration before it is known.
- **The code after it uses that configuration's names.** An address it uses that's something else in that configuration than usual gets a plain name there: e.g. after `lda #$34 : sta $01` (RAM only), `lda $d020` is `lda ld020` rather than `lda vic_border_colour`, and `lda $e000` is `lda le000`. These names are listed under their own heading, `; Other memory configurations`, at the end of the memory locations. A call to a Kernal or BASIC routine that's switched out isn't commented as one (e.g. `jsr lffd2`, not `jsr CHROUT`), and a store to a colour register that's switched out doesn't store a colour.
- **The configuration is followed as the code runs:** to the next instruction, the targets of branches and JMPs, and a subroutine called with JSR. The code after a JSR continues with the configuration the call was made with, unless the subroutine always returns with one it sets itself. Where code can be reached with different configurations, or from an entry point or another way that isn't known (e.g. an interrupt handler whose address the program stores in a vector), its configuration isn't known, so it's taken to be the usual one, $37 (BASIC, the Kernal and the I/O).

The configurations are those of bits 0-2 of $01 (LORAM, HIRAM and CHAREN), without a cartridge, which changes them.

`commodore.c64_configuration(start, end, configuration)`

Says that the code from `start` to `end` (runtime addresses, `end` not included) runs with the given configuration (the value of $01), e.g. an interrupt handler that runs with $35, which the code that sets $01 before enabling the interrupt gives it. The addresses it uses are named as above. Call it after `c64()`.

`commodore.c64_memory(configuration, addr)` says what's at an address in a configuration (`"RAM"`, `"BASIC ROM"`, `"Kernal ROM"`, `"I/O"` or `"character ROM"`), and `commodore.c64_configuration_description(configuration)` describes a configuration, as in the comments.

## Names

py8dis's names are only used where nothing else names the address. One isn't used if its name is given to another address (e.g. a control file's `label(0x0964, "key")`, when Commodore's name for $ea31 is `KEY`), so that the name isn't defined twice. Names are compared in lower case for this, since some assemblers (e.g. 64tass) take `key` and `KEY` to be the same name.

Commodore's own names are in capitals, as in its documentation and source: the Kernal's calls (`CHROUT`), the labels from its source (`PLOT_ROM`, `VDCOUT`), and with `names="commodore"` the locations, registers and routines (`EXTCOL`, `STROUT`). py8dis's descriptive names are in lower case (`vic_border_colour`, `basic_print_string`), so with `names="descriptive"`, a location with no descriptive name of its own (e.g. much of the C128's, Plus/4's and 1541's workspace) has Commodore's name, in capitals. `config.set_upper_case_os_calls(False)`, before `c64()` etc., puts them all in lower case (as for the Acorn MOS's calls).

The C128's, Plus/4's and PET's workspace (zero page and $0200 up) has Commodore's names from its source. With the default `names="descriptive"`, the locations that are the C64's have its descriptive names (e.g. `jiffy_clock`, `keyboard_buffer_length`), and the most used of the rest have descriptive names of their own (e.g. the C128's `screen_mode_40_80`, `vdc_screen_base`, `function_key_lengths`). The others have Commodore's names either way, since there are hundreds and most are BASIC's or the monitor's. The hardware's names are descriptive with `names="descriptive"`, and Commodore's (from its source, e.g. `MMUCR`, `VDCADR`, `TEDIRQ`) with `names="commodore"`.

## VIC-20

`commodore.vic20(expansion=None, names="descriptive", rom_labels=True)`

The same for the VIC-20, whose Kernal and BASIC are the C64's, with its own hardware and memory map: the VIC (`vic_background_border_colour`, `vic_voice1_frequency`...), the two VIAs (`via1_port_a`..., or Commodore's `D1ORA`...), the colour RAM, the character ROM, the screen, its own ROM routines (e.g. `kernal_irq_handler` at $eabf) and the labels in Commodore's source for its ROMs. Its jump table lacks the C64's first three entries. Commodore gave the VIC's registers no names of their own, so with `names="commodore"` they're `VICREG`, `VICREG+1` and so on, as in its source.

`expansion` is the RAM expansion: `"none"`, `"3k"` (block 0, $0400-$0fff) or `"8k"` (8K or more, from $2000). It decides where a BASIC program starts ($1001, $0401 or $1201) and where the screen and its colour RAM are ($1e00 and $9600, or with 8K or more, $1000 and $9400). By default it's worked out from where the program is loaded: `"3k"` if there's data at $0401, else `"none"` if there's data at $1001, else `"8k"` if there's data at $1201.

## C128

`commodore.c128(names="descriptive", rom_labels=True)`

The same for the C128 in C128 mode, with the usual bank 15 (the ROMs, and the I/O at $d000): its workspace, the MMU (`mmu_configuration` at $ff00, `mmu_ram_configuration`...), the VDC (`vdc_address` and `vdc_data` at $d600), the VIC-II, the SID and the CIAs as on the C64, a BASIC program at $1c01, and the labels in Commodore's source for its BASIC, monitor, screen editor and Kernal (a screen editor or monitor label with the same name as another has `_editor` or `_monitor` added). Its jump table is the C64's and 19 more at $ff47-$ff7d, e.g. `JSRFAR`, `SETBNK` and `PRIMM`, whose inline string is marked, and skipped when tracing:

```
    jsr PRIMM             ; Print the zero-terminated string that follows the JSR
    !pet "hello, c128", $0d, 0
```

**Calls to other banks.** A call to another bank with JSRFAR or JMPFAR, whose bank and address are set up at $02-$04 with known values (in any order, with any registers and other instructions between them and the call), is commented, e.g. `; Call far_call_target in bank 0`. If the address is in the program, in a bank that has RAM 0 there, where the program is (banks 0 and 2, and below their ROMs, 4, 6, 8, 10 and 12-15), it's traced as code, named `far_call_target` (or `far_jump_target`, then `_2` etc.) unless it already has a name, and the set-up uses its name:

```
    ; Call far_call_target in bank 0
    lda #0
    sta far_call_bank
    lda #>far_call_target
    sta far_call_pc_high
    lda #<far_call_target
    sta far_call_pc_low
    jsr JSRFAR
```

**The MMU's configuration.** The names assume the C128's usual bank 15: the ROMs, with I/O at $d000. In another configuration of its MMU, the same addresses can be something else, e.g. RAM rather than the VIC-II or the Kernal ROM. So:

- **The code that sets the MMU's configuration is commented** with what it sets, when the value stored to its configuration register ($ff00, or $d500) is known, e.g. `sta mmu_configuration ; Set the MMU to bank 0 (RAM 0 only)`, or `; Set the MMU to RAM 0, I/O` for one that isn't one of the Kernal's 16 banks. A store to one of its load configuration registers ($ff01-$ff04) is commented too, e.g. `; Set the MMU to preconfiguration A (as set at $d501)`.
- **The code after it uses that configuration's names.** An address it uses that's something else in that configuration than in bank 15 gets a plain name there, e.g. after `lda #$3f : sta $ff00` (bank 0), `lda $d020` is `lda ld020` rather than `lda vic_border_colour`. These names are listed under their own heading, `; Other banks`, at the end of the memory locations, since their addresses' regions are bank 15's.
- **The configuration is followed through the code as it runs:** to the next instruction, the targets of branches and JMPs (so a loop after a change of configuration runs with it too), and a subroutine called with JSR, up to the next change. The code after a JSR continues with the configuration the call was made with, unless the subroutine always returns with one it sets itself (e.g. a routine that switches to bank 0); after PRIMM, it continues with the code after its string.
- Where code can be reached with different configurations, or from an entry point or some other way that isn't known (e.g. a vector the program sets), its configuration isn't known, so it's taken to be bank 15. A JSRFAR or JMPFAR target runs with its bank's configuration.
- $0000-$03ff is RAM 0 in every bank (the Kernal's common RAM), so its names stay. Only the names `c128()` gives are replaced, not the control file's.
- A call to a Kernal or BASIC routine that isn't there in that configuration isn't one, so it's not commented (e.g. `jsr lffd2`, not `jsr CHROUT ; Output 'a'`), and a store to a colour register that isn't there doesn't store a colour.

`commodore.c128_bank(start, end, bank=None, *, configuration=None)`

Says that the code from `start` to `end` (runtime addresses, `end` not included) runs with the MMU set to `bank` (0-15, as the Kernal numbers them) or `configuration` (the value of its configuration register), e.g. a routine whose caller sets the bank. The addresses it uses are named as above. Call it after `c128()`.

- Since this is known before the code is traced, a call to PRIMM ($ff7d) there with the Kernal ROM mapped out is traced as an ordinary call, without the string after it. (After code that sets the configuration, that isn't known until the code has been traced, so it's still treated as PRIMM.)
- Code after a change of configuration in the range follows that change. Code reached from outside the range runs with the range's configuration, whatever the code that calls or jumps to it would give.

`commodore.c128_memory(configuration, addr)` says what's at an address in a configuration (e.g. `"I/O"`, `"Kernal ROM"`, `"RAM 1"`), and `commodore.c128_configuration_description(configuration)` describes a configuration, as in the comments above.

## Plus/4

`commodore.plus4(names="descriptive", rom_labels=True)`

The same for the Plus/4 (and the C16 and C116, which have the same ROMs): its workspace, the TED at $ff00-$ff3f (the timers, video, sound, keyboard latch, interrupts, and the ROM switch at $ff3e/$ff3f: `ted_rom_select`, `ted_ram_select`), the ACIA at $fd00, the 6529 ports, the screen and its attributes, a BASIC program at $1001, and the labels in Commodore's source for its BASIC and Kernal. Its jump table is the C64's with `PRINT`, `PRIMM` (as on the C128) and `MONITR`. The TED's colours include their luminance, so they aren't named as constants.

## PET

`commodore.pet(basic=4, columns=40, names="descriptive", rom_labels=True)`

The same for the PET (and the CBM 3000, 4000 and 8000 series), with BASIC 1 (the original 1977 ROMs), 2 or 4, whose workspace and ROM addresses differ (e.g. the IRQ vector is at $0219 with BASIC 1, and $0090 with BASIC 2 and 4), and a 40 or 80 column screen (`columns=80`, only with BASIC 4: the 8000 series, with its CRTC at $e880 as `crtc_address` and `crtc_data`, and the 80-column editor's workspace, e.g. `window_top`). It names:

- the two PIAs (`pia1_port_a`, ... `pia2_control_b`; Commodore's `PIAL`, `IEEI`...), the VIA at $e840 (`via_port_b`... `via_peripheral_control`; `PIA`, `SYNC`... in Commodore's source) and the screen at $8000;
- the Kernal's jump table at $ffc0-$ffea (`OPEN`, `CHKIN`, `CHROUT`, `GETIN`, `STOP`, `UDTIM`...). Only `CHROUT` has its own comments (`Output $93 (clear screen)`): `LOAD`, `SAVE`, `VERIFY` and `SYS` there are BASIC's commands, which read their parameters from the BASIC text, not the C64's Kernal calls;
- its ROM routines (`basic_print_string`, `basic_print_number`, `kernal_irq_handler`, the IRQ handler programs end with, e.g. $e455 with BASIC 4...) and the labels in Commodore's source for its BASIC and Kernal (Martin Hoffmann-Vetter's reconstructions, which assemble to the ROMs VICE uses). BASIC 4's screen editor at $e000 is different for each model, so its labels are left out;
- a BASIC program at $0401, listed with that version's keywords (BASIC 4's disk commands, e.g. `CATALOG`, too), and code that sets the IRQ, BRK or NMI vector.

The PET has no colours. `is_cartridge()` and `basic_rom()` aren't supported for it, since its expansion ROMs and BASIC ROM have no standard header or vectors.

## 1541 disk drive

`commodore.drive1541(rom="1541", names="descriptive", rom_labels=True)`

The same for code that runs in the 1541 disk drive's own 6502, e.g. a fast loader's drive code (which a C64 program sends with `M-W` and runs with `M-E` or a job), or the drive's DOS ROM itself. It names:

- the DOS's workspace (Commodore's names from its source, with descriptive names for the most used, e.g. `job_queue`, `job_track_sector`, `buffer_pointer`, `drive_number`), and the five buffers at $0300-$07ff (`buffer_0` to `buffer_4`, except those the code is loaded in);
- the two VIAs: VIA 1 at $1800, the serial bus (`via1_serial_bus`, ...), and VIA 2 at $1c00, the disk controller (`via2_disk_control`, for the motors, LED, write protect sensor, bit rate and sync; `via2_disk_data`, the GCR data from or to the disk), with Commodore's names (`PB`, `DSKCNT`, `DATA2`...) with `names="commodore"`;
- the DOS ROM's routines that drive code calls (`wait_for_sync`, `gcr_to_binary`, `end_job`, `dos_idle_loop`...) and the labels in Commodore's source for the ROM, and code that sets the NMI vector at $0065.

**Jobs are commented.** Code that writes a job code to the job queue ($00-$04, one for each buffer; the 1541 has no buffer for a sixth at $05), however it does it, is commented with the job, with its track and sector ($06-$0f) if they're set too, and the job code is named, e.g.:

```
    ; Job 0: read track 18, sector 1 into buffer 0 ($0300)
    lda #$12
    sta job_track_sector
    ldx #1
    stx job_track_sector+1
    lda #job_read
    sta job_queue
```

For a JUMP or EXECUTE job, which runs the code in the job's buffer, that code is traced, if it's loaded, and named (e.g. `job_3_code`).

**Job results are named.** The result the disk controller leaves in the job queue, where code compares it after reading the queue (`lda job_queue : bmi wait : cmp #job_ok`), or gives it to ERRR to end a job (`lda #job_ok : jmp end_job`), is named as a constant, with the error the DOS reports for it, e.g. `job_no_sync = 3 ; 21 READ ERROR: no sync mark`.

**The VIAs' bits are described.** A store to VIA 1's or VIA 2's port B, after `lda` of the port then `ora #n` or `and #n`, or of a known value, is commented with what it does, e.g. `; Turn the LED on`, `; Turn the motor on, set the bit rate to 3 (for tracks 1-17)` or `; Pull the clock line low`. A test of an input bit (`lda $1800 : and #$04`, or `bit $1c00`) is commented too, e.g. `; Test CLOCK IN` or `; Test SYNC (clear at a sync mark)`.

`rom` is `"1541"` (DOS 325302-01 and 901229-05, the default) or `"1541-ii"` (251968-03, the 1541-II's and 1541C's), which only changes a few ROM labels.

### Drive code in a C64 program

`commodore.drive1541_code(runtime_addr, binary_addr, length, rom="1541")`

For a C64 (or other) program with code for the drive in it, e.g. a fast loader's, which the program sends to the drive with `M-W` and runs with `M-E` or a job: the `length` bytes at `binary_addr` run at `runtime_addr` in the drive. Call it after `c64()` etc.

The bytes are moved there (see `move()`; the move ID is returned) and traced from there. Where the drive code uses an address outside itself, it gets the 1541's name, as `drive1541()` gives (e.g. `job_queue`, `via2_disk_control`, `wait_for_sync`), rather than the C64's name for that address (which is the 6510's port at $00, or the screen at $0400). These names are defined under the heading `; 1541 drive`, with `_drive` added to one that's also a C64 name; so is an address with no 1541 name that only the drive code uses (e.g. `l0300` in buffer 0, when the drive code is in buffer 0 too), rather than under the C64's heading for it. Its jobs are commented, and a JUMP or EXECUTE job's code is traced if it's in drive code too. Calls to the DOS ROM's routines are commented, and aren't taken to be calls to the C64's ROM. A name the control file gives an address is kept.

```python
start = load_prg("fastload.prg", "6510")
commodore.c64()
drive_move = commodore.drive1541_code(0x0500, 0x083b, 0x0111)   # $083b-$094b runs at $0500 in the drive
label(0x0500, "drive_code", drive_move)
```

### The DOS ROM

`commodore.dos_rom()`

For disassembling the 1541's DOS ROM (loaded at $c000, after `drive1541()`): traces the code from the vectors at its end (`format`, `motor_off` and the user commands U1 and U2; U3-U8's, at $0500-$050f in buffer 2, are named but not traced) and the 6502's vectors.

## BASIC programs

`commodore.basic_program(runtime_addr=None)`

Marks the tokenised BASIC program at `runtime_addr`, by default where BASIC programs start on the machine (`c64()` etc. do this; the 1541 has no BASIC, so give the address there), such as the one-line `10 SYS2061` most machine code programs start with. Each line is labelled (`basic_line_10`), its link to the next line and its line number are words, and its text is bytes for the tokens and PETSCII strings, with the line listed in a comment, with the machine's BASIC's keywords (V2's; BASIC 1's, 2's or 4's on the PET; 3.5's on the Plus/4; and 7.0's on the C128, including its two-byte ones, e.g. `BANK`, $fe $02):

```
; 10 SYS2061
basic_line_10
    !word basic_end
    !word 10
    !byte $9e
    !pet "2061"
    !byte 0
basic_end
    !word 0
```

An address that SYS calls in the loaded data is traced as code, and named `sys_entry` unless it already has a name (so to name it yourself, do so before calling `c64()`). Returns the address after the program, or None if there isn't a BASIC program there.

## Cartridges and ROMs

`commodore.is_cartridge()`

For a cartridge: names its header (the cold and warm start vectors, and the signature: `CBM80` at $8004 on the C64, `A0CBM` at $a004 on the VIC-20) and traces the code they point to. On the C128 and Plus/4, a function ROM at $8000 starts with its cold and warm start code (usually JMPs) rather than vectors, then an ID byte and `CBM` in ASCII; these are named and the code traced. Call it after `c64()` etc.

`commodore.kernal_rom()` and `commodore.basic_rom()`

For disassembling a Kernal ROM (at $e000, or $c000 on the C128 and Plus/4) or BASIC ROM (at $a000 on the C64, $c000 on the VIC-20, $4000 on the C128, $8000 on the Plus/4) itself: they trace the code from the Kernal's jump table and the 6502's vectors, or BASIC's cold and warm start vectors (or JMPs, on the C128 and Plus/4). `examples/python/open_roms_kernal.py` and `open_roms_basic.py` disassemble the ROMs of [MEGA65's Open ROMs](https://github.com/MEGA65/open-roms), a free replacement for the C64's.
