# CP/M

For a CP/M program, load it as Z80 or 8080 code at $0100 and add `cpm.cpm()`:

```python
from commands import *
import cpm

load(0x0100, "program.com", "z80")
cpm.cpm()
entry(0x0100)
go()
```

## What it does

**Names page zero**, if the program uses it: `warm_boot`, `iobyte`, `current_drive`, the BDOS's entry point `BDOS` (with `BDOS+1` for the address of the BDOS, which is the top of the memory programs can use, e.g. `ld hl,(BDOS+1)`), `default_fcb` and `second_fcb` (the file names in the command) and `default_dma` (the command's tail, and the default DMA buffer), with e.g. `default_fcb+1` for the bytes after them.

**Comments calls to the BDOS** (`call BDOS`, or a jump, conditional or not) with what the function does, when its number in C is known, e.g. `call BDOS ; Print the string at DE, up to a '$'`, or `Write 'A' to the console` when E is known too. The `ld c,n` that sets C is given the function's name, as a constant:

```
    ld de,message
    ld c,C_WRITESTR
    call BDOS                ; Print the string at DE, up to a '$'
```

The names are those of Digital Research's CP/M 3 documentation (see [seasip.info](https://www.seasip.info/Cpm/bdos.html)), for the functions of CP/M 2.2 and CP/M 3. `BDOS`, `C_WRITESTR` and the rest are in capitals, unless `config.set_upper_case_os_calls(False)` is used first (then `bdos` and `c_writestr`).

**Names the address in DE**, for the functions that take one (a string to print, a buffer for a line of input, a file control block or a DMA buffer), when it's loaded with `ld de,nn`: `ld de,default_fcb`. A string to print is marked as a `$` terminated string, and named `message` if it has no name yet; an FCB in the program is named `fcb`, a buffer `input_buffer` and a DMA buffer `dma_buffer`, if they have no name.

## A program's own BDOS routine

`cpm.bdos_wrapper(runtime_addr, register="c")`

Many programs call the BDOS through a routine of their own (e.g. one that saves the registers first). This says that the routine at `runtime_addr` does, with the function number in the register: `"c"` (as the BDOS has it) or `"a"`. Calls to it are then commented in the same way. Call it after `cpm.cpm()`.

See `examples/python/bbcbasic.py`, `zexdoc.py` and `cpm_8080.py`.
