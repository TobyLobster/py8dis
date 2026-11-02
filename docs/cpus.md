# CPUs

The CPU is chosen when the program is loaded: `load(addr, filename, cpu_name)`, where `cpu_name` is one of:

| `cpu_name` | CPU                                                       | Assemblers |
| ---------- | --------------------------------------------------------- | ---------- |
| `"6502"`   | the 6502, its documented instructions                     | acme, beebasm, Baron, xa, 64tass, ca65 |
| `"6510"`   | the 6502 with its undocumented opcodes (as on the Commodore 64's 6510, and any NMOS 6502) | acme, beebasm, Baron, xa, 64tass, ca65 |
| `"65C02"`  | the 65C02 (as in the BBC Master)                          | acme, beebasm, Baron, xa, 64tass, ca65 |
| `"8080"`   | the Intel 8080                                            | z88dk-z80asm |
| `"Z80"`    | the Z80, with its undocumented opcodes                    | z88dk-z80asm, sjasmplus |

(The names can be in either case.)

## The 6502's undocumented opcodes

With `"6510"`, the 6502's undocumented opcodes are traced as what they do (with their cycle counts, and what's known of the registers afterwards), so that code that uses them is disassembled properly: SLO, RLA, SRE, RRA, SAX, LAX, DCP, ISC, ANC, ALR, ARR, SBX, SBC (&EB), NOP with operands, JAM, and the unstable ANE, LXA, LAS, TAS, SHA, SHX and SHY.

How they're written depends on the assembler:

- **acme** uses its own mnemonics (after `!cpu 6510`; ALR is written as ASR, which older versions of acme need);
- **64tass** uses py8dis's (after `.cpu "6502i"`);
- **ca65** uses its own (after `.setcpu "6502X"`; LXA is `lax #imm` and SBX is `axs`).

Where an instruction has several opcodes and the assembler uses another one for it (e.g. ANC &2B, or most of the NOPs), it can't be written as an instruction. The same 70 opcodes are written as instructions for all three. The rest, and all of them for beebasm, Baron and xa, are written as data bytes with the instruction in a comment, e.g. `equb &a7, l0070 ; lax l0070 (undocumented)`.

With `"6502"` they aren't traced: tracing stops at one, since taking unknown opcodes to be code would turn data into nonsense instructions.

## The 8080

**Mnemonics.** The output uses Intel's mnemonics, for z88dk-z80asm's `-m8080`, with two exceptions that z88dk-z80asm needs:

- $F2 and $F4 (jump and call if plus) are written `jp p,` and `call p,`, as on the Z80, since z88dk-z80asm takes Intel's `jp` and `cp` to be the Z80's (an unconditional jump, and a compare);
- RST is written with its address, e.g. `rst $08` for RST 1, since z88dk-z80asm takes the operand to be the address.

**RST** is traced as a call, as on the Z80 (see below). Code called by CALL or RST gets a `sub_` label.

## The Z80

**Undocumented opcodes.** `"Z80"` includes the Z80's undocumented opcodes, since Z80 code often uses them, and they're traced as what they do (with their cycle counts). The ones the assembler accepts are written as instructions: those that use IXH, IXL, IYH and IYL (e.g. `ld ixh,a`), SLL, the indexed rotates, shifts, SET and RES that copy the result to a register (e.g. `rlc (ix+2),b`), `in f,(c)` and `out (c),0`. The others are written as data bytes with the instruction in a comment, e.g. `db $ed, $4c ; neg (undocumented)`:

- the duplicates (another encoding of an instruction, such as ED 4C, a second NEG);
- the ED opcodes that do nothing;
- a DD or FD prefix before an instruction that doesn't use HL. The prefix does nothing, so it's written as a byte on its own, `db $dd ; prefix with no effect (undocumented)`, followed by the instruction.

**RST** is traced as a call to its address (which, if it's loaded, gets a label such as `rst_08`), returning to the next instruction, unless a subroutine hook (see [`hook_subroutine()`](commands.md#hook_subroutine)) says otherwise, e.g. for data that follows it. (The ZX Spectrum's RST $08 and RST $28 are like this: see [machines/spectrum.md](machines/spectrum.md).)

**Index registers.** A displacement is written as a signed number, e.g. `ld a,(ix-3)`, or as the expression given with `expr()` at its byte.

**Return addresses pushed onto the stack.** `ld rr,nn` then `push rr` (e.g. so that a routine jumped to returns there) is traced as code, and named in the `ld`, e.g. `ld hl,resume : push hl : jp clear_screen`. py8dis takes it to be a return address if:

- following the code on from the PUSH, along every path (but not into calls, which are taken to return), a RET or RET cc is reached with it at the top of the stack, or the stack pointer is stored (`ld (nn),sp`, so that the code can return there later, as the ZX Spectrum's ROM does with ERR_SP);
- and no path takes it off the stack first (with a POP, `ex (sp),hl` or a change to SP).

A value pushed to be popped later isn't taken to be one. A return address that's taken off the stack again on some path (e.g. one for errors, which the code throws away when there's no error) isn't found, so it needs `entry()` and `expr()`.

## What py8dis knows about the registers

As it goes through the code, py8dis keeps track of what it knows for certain about the registers and flags after each instruction, from the code before it, back to a label (where the code can come from somewhere else). This is the CPU state. It's used for comments, e.g. on an OS call when A is known, and `config.set_show_cpu_state(True)` shows it after each instruction.

For the 6502:

- after a conditional branch that isn't taken, its flag is known;
- after a BNE that isn't taken, so is the register whose result set Z: it's 0 after e.g. `dey : bne loop` or `lda $70 : bne skip`, and after a compare with an immediate value it's that value, e.g. A is $7B after `cmp #$7b : bne skip` (and X is 3 after `cpx #3 : bne skip`);
- a branch to the next instruction says nothing.

For the 8080, A to L, SP and the flags S, Z, P, CY and AC are tracked.

For the Z80, the registers (including IX, IY, their halves, I and the alternate set) and the flags S, Z, H, P/V, N and C are tracked. The state is shown like this: `A:41 BC:12-- DE:---- HL:---- IX:---- IY:---- SP:---- sZh-nc`, where `--` is a byte that isn't known, and a flag is upper case if it's set, lower case if it's clear, or `-` if it isn't known. Also:

- memory isn't tracked, so a value loaded from memory isn't known;
- a call (or RST) could change anything;
- after a conditional jump or return that isn't taken, its condition is known to be false (e.g. Z is set after `jr nz` falls through), as is B after DJNZ (it's 0), and BC after LDIR (0).

## Redundant instructions

For the 6502 and the Z80, an instruction whose results are never used is commented `; Redundant instruction?`. That's when every register and flag it changes is changed again before anything reads it, e.g. `lda foo` just before `pla`, or `lda foo : and #3` before `lda bar` (both are redundant), or `sec` before `cmp`. This can point to a bug, or to code that was left behind. `config.set_redundant_instruction_comments(False)` turns it off.

It's only looked for within a straight run of code: a label, a branch, a call or the end of the run counts as reading everything.

On the 6502, only instructions that just change registers and flags can be redundant: loads, transfers, arithmetic and logic, compares, shifts of A, CLC, SEC and CLV. An instruction isn't redundant if it reads memory mapped I/O (see [`io_range()`](commands.md#io_range)), or reads an address that isn't known (an indirect load), or if code jumps into the middle of it (the BIT trick, e.g. `bit $02a9` skipping `lda #2`).

On the Z80, the same is done, e.g. `ld a,(hl)` just before `pop af`, or `scf` before `cp`. The instructions that can be redundant are: loads into registers (not `ld (hl),a` etc., nor `ld i,a` or `ld r,a`), INC and DEC of registers, arithmetic and logic, compares, rotates and shifts, BIT, RES and SET of registers, DAA, CPL, SCF, CCF, NEG and `ex de,hl`. IN isn't, nor is a read of memory mapped I/O; with any I/O named, a read through HL, BC, DE, IX or IY isn't either, since its address isn't known. A CALL, RST, jump or return (including `ret cc`) counts as reading everything.
