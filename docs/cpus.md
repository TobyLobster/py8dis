# CPUs

The CPU is chosen when the program is loaded: `load(addr, filename, cpu_name)`, where `cpu_name` is one of:

| `cpu_name` | CPU                                                       | Assemblers |
| ---------- | --------------------------------------------------------- | ---------- |
| `"6502"`   | the 6502, its documented instructions                     | acme, beebasm, Baron, xa, 64tass, ca65, Merlin 32 |
| `"6510"`   | the 6502 with its undocumented opcodes (as on the Commodore 64's 6510, and any NMOS 6502) | acme, beebasm, Baron, xa, 64tass, ca65, Merlin 32 |
| `"65C02"`  | the 65C02 (as in the BBC Master)                          | acme, beebasm, Baron, xa, 64tass, ca65, Merlin 32 |
| `"8080"`   | the Intel 8080                                            | z88dk-z80asm |
| `"Z80"`    | the Z80, with its undocumented opcodes                    | z88dk-z80asm, sjasmplus |

(The names can be in either case.)

## The 6502's undocumented opcodes

With `"6510"`, the 6502's undocumented opcodes are traced as what they do (with their cycle counts, and what's known of the registers afterwards), so that code that uses them is disassembled properly: SLO, RLA, SRE, RRA, SAX, LAX, DCP, ISC, ANC, ALR, ARR, SBX, SBC (&EB), NOP with operands, JAM, and the unstable ANE, LXA, LAS, TAS, SHA, SHX and SHY.

How they're written depends on the assembler:

- **acme** uses its own mnemonics (after `!cpu 6510`; ALR is written as ASR, which older versions of acme need);
- **64tass** uses py8dis's (after `.cpu "6502i"`);
- **ca65** uses its own (after `.setcpu "6502X"`; LXA is `lax #imm` and SBX is `axs`).

Where an instruction has several opcodes and the assembler uses another one for it (e.g. ANC &2B, or most of the NOPs), it can't be written as an instruction. The same 70 opcodes are written as instructions for all three. The rest, and all of them for beebasm, Baron, xa and Merlin 32, are written as data bytes with the instruction in a comment, e.g. `equb &a7, l0070 ; lax l0070 (undocumented)`.

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

As it goes through the code, py8dis keeps track of what it knows for certain about the registers and flags after each instruction, from the code before it, back to a label (where the code can come from somewhere else; on the 6502, from the ways into the label, as below). This is the CPU state. It's used for comments, e.g. on an OS call when A is known, and `config.set_show_cpu_state(True)` shows it after each instruction.

For the 6502, what's known at a label is what all the ways into it agree on, where they're all known: the instruction before it (if the code runs on into it) and the branches to it. On a branch's way in, the branch's flag is as it is when the branch is taken, with what follows from that: e.g. A is less than 7 at `ok` after `cmp #7 : bcc ok`, and A is 0 at `zero` after `lda $70 : beq zero`. Loops are worked out until what's known at their labels settles, so e.g. a counter that goes from 0 to 3 round a loop is known to be 0 to 3 at the labels in it and after it (a range that's still growing after 32 times round is taken to the end it's growing towards). Nothing is known at a label where code could come from somewhere else:

- an entry point (from `entry()`, a vector, `code_ptr()`, a jump table, etc.);
- the target of a JSR or JMP (a subroutine could be called from code that py8dis doesn't see, e.g. through a vector, and a JMP's target is often a routine of its own);
- a label that an expression names (e.g. a word in a table written as its name), or that anything other than a branch refers to (e.g. an instruction that reads it), or that nothing refers to (e.g. one given with `label()`), or a label reached from another move;
- an instruction after data (e.g. after a string that a subroutine's hook skips).

`config.set_join_states_at_labels(False)` makes py8dis forget everything at every label instead, as it did before.

After a JSR to a subroutine in the code, what's known is what the subroutine leaves behind, whoever calls it:

- the registers and flags it never changes (on any path to an RTS, counting the subroutines it calls and those it jumps to) are as they were before the call;
- the rest are what's known at all of its RTSs (worked out knowing nothing at its start, since it could be called from anywhere), e.g. that it always returns with the carry clear;
- a subroutine that jumps (or branches, or runs on) into another leaves what that one leaves too.

Nothing is known after a call to a subroutine whose use of the stack py8dis doesn't follow: one that returns with something still pushed (e.g. the RTS trick), pulls more than it pushed (e.g. throwing its return address away), uses TXS, RTI, BRK or an indirect jump, runs into data, or calls such a subroutine, or one with a hook (see `hook_subroutine()`); nor after a call to code outside the binary (e.g. an OS routine). Before a subroutine, an "On Exit" note says what it leaves behind that the code after a call to it relies on: a register's value or a flag (`C: clear`), and then, on one line, the registers and flags it doesn't change (`X is preserved`, or e.g. `X, Y and C are preserved`), when something after a call reads them before changing them. A subroutine whose `subroutine()` gives its own `on_exit` notes doesn't get them. `config.set_subroutine_summaries(False)` turns this off (nothing is known after a JSR).

Also, for the 6502:

- A, X and Y are known bit by bit, so a register can be partly known: e.g. after `and #$0f` its top four bits are 0, after `ora #$80` bit 7 is 1, and after `asl` bit 0 is 0. AND, ORA and EOR with an immediate value, the shifts and rotates of A, INX, DEX, INY, DEY (and the 65C02's INC A and DEC A) and the transfers work on the bits that are known, and the flags they set are known where the bits say what they are: e.g. N is clear after `lsr`, Z is clear after `ora #1`, and C is clear after `and #$7f : asl`;
- each register's range (the least and greatest value it could be) is known as well, which can say more than its bits: e.g. after `cmp #7 : bcs skip` A is 0 to 6 (C clear means it's less than 7, and C set after `cmp #2 : bcc skip` means it's at least 2), and after `asl` it's 0 to 12. The bits that every value in the range shares are known too, e.g. the top five for 0 to 6. What a compare says is forgotten once the register changes, e.g. after `cmp #7 : lda $70 : bcs skip`;
- a compare with an immediate value sets the flags as far as the register's known bits and range say: e.g. after `and #$0f`, `cmp #$10` clears C (A is less than $10). ADC and SBC with an immediate value are only worked out when D is known to be clear (in decimal mode the result is different);
- a rotate of memory puts C into bit 7 or bit 0: so `sec : ror flag` sets N (and clears Z), and LSR of memory always clears N;
- after a conditional branch that isn't taken, its flag is known;
- after a BNE that isn't taken, so is the register whose result set Z: it's 0 after e.g. `dey : bne loop` or `lda $70 : bne skip`, and after a compare with an immediate value it's that value, e.g. A is $7B after `cmp #$7b : bne skip` (and X is 3 after `cpx #3 : bne skip`);
- after a BEQ that isn't taken, that register isn't that value: so if only one of its bits isn't known, that bit is known, e.g. A is 1 after `and #1 : beq skip`;
- after a BPL or BMI that isn't taken, bit 7 of the register whose result set N is known, e.g. bit 7 of A is set after `lda $70 : bpl skip`;
- a branch to the next instruction says nothing.

The state is shown like this: `A:0- X:-- Y:00 n---Zc`, where each register is shown as two hex digits, with `-` for a digit that isn't wholly known (so `0-` is a value from 0 to $0F), and each flag is upper case if it's set, lower case if it's clear, `-` if it isn't known, or `?` if it's unknown but follows from a compare (a BNE that isn't taken then says C is set). The JSON output has the known bits of a register that's partly known, e.g. `"a_bits": "0000----"`.

What's known is used for comments, which are all on by default:

- a register's value, when an instruction changes it to one that's known, e.g. `; Y=1` on the `iny` of `ldy #0 : ... : iny`;
- an ADC with carry set, or an SBC with carry clear, e.g. `; Carry is set, so adding 4` on the `adc #3` of `cmp $71 : bne skip : adc #3`;
- a conditional branch that's always taken, `; ALWAYS branch`, e.g. the `bmi` of `ora #$80 : bmi skip`;
- a rotate with the carry known, `; Rotate in a set bit` or `; Rotate in a clear bit`, e.g. `sec : ror flag`; and a rotate or shift of A whose bit shifted out is known, e.g. `; Shift clear bit out (clears carry)` on the `asl` of `and #$7f : asl : adc #1`, but only if the carry is relied on afterwards: an instruction reads it (ADC, SBC, ROL, ROR, BCC, BCS or PHP) before anything sets it (so not on the first two of `asl : asl : asl`, nor before a jump, call or return, e.g. the RTS of the RTS trick);
- where a register whose value is known was set well before (more than four instructions back, or before a label, e.g. round a loop), the value a store stores, e.g. `; A=0` on the `sta table,y` of `lda #0 : tay : loop: sta table,y : iny : bne loop`, and the index of an indexed instruction, e.g. `; Offset Y=$11` on `sta (ptr),y` (not just after `ldy #$11`, where it's plain). A value isn't said again while it's the same and there's no label in between, e.g. only the first of `stx a : stx b` says `; X=0`.

An immediate operand that the code itself changes (self-modifying code, e.g. `sta modified+1 : ... modified: ldx #0`) isn't taken to be known: the instruction is treated as if its operand came from memory. That's any operand that an instruction in the traced code writes to with an address (zero page or absolute, not indexed or indirect).

For the 8080, A to L, SP and the flags S, Z, P, CY and AC are tracked.

For the Z80, the registers (including IX, IY, their halves, I and the alternate set) and the flags S, Z, H, P/V, N and C are tracked. The state is shown like this: `A:41 BC:12-- DE:---- HL:---- IX:---- IY:---- SP:---- sZh-nc`, where `--` is a byte that isn't known, and a flag is upper case if it's set, lower case if it's clear, or `-` if it isn't known. Also:

- memory isn't tracked, so a value loaded from memory isn't known;
- a call (or RST) could change anything;
- after a conditional jump or return that isn't taken, its condition is known to be false (e.g. Z is set after `jr nz` falls through), as is B after DJNZ (it's 0), and BC after LDIR (0).

## Jump tables

On the 6502, py8dis finds jump tables itself when it knows the possible values of the index (from the code before it, in the same straight run: see above), and marks each entry as the address of code, as [`code_ptr()`](commands.md#code_ptr) would: the code is traced, and each entry is written as its label, with a comment before the table. E.g. in

```
    cmp #7
    bcs bad
    asl
    tax
    lda table+1,x
    pha
    lda table,x
    pha
    rts
```

X is 0, 2, ... or 12, so the table has 7 entries (each the address minus 1, for the RTS). The ways of jumping through a table it finds:

- the RTS trick: pushing the high byte, then the low byte, then RTS;
- storing the address and jumping through it: `lda lo,x : sta ptr : lda hi,x : sta ptr+1 : jmp (ptr)`;
- storing the address in the operand of a JSR or JMP that follows (self-modifying code);
- the 65C02's `jmp (table,x)`.

The low and high bytes can be in two tables, or together as words. A table isn't marked if any of its bytes is already classified or has an expression (so a control file can mark it itself, e.g. with [`rts_code_ptr()`](commands.md#rts_code_ptr)), if its entries overlap, if an entry points into the table or into an instruction or data, or if the index has more than 64 possible values. The index must be bounded by code that py8dis can follow to the table, including through the branches to labels on the way (see above), e.g. `cpx #10 : bcc ok : ... ok: lda table,x`, or a loop's counter; a bound in a subroutine's caller isn't seen. `config.set_find_jump_tables(False)` turns it off.

## Redundant instructions

For the 6502 and the Z80, an instruction whose results are never used is commented `; Redundant instruction?`. That's when every register and flag it changes is changed again before anything reads it, e.g. `lda foo` just before `pla`, or `lda foo : and #3` before `lda bar` (both are redundant), or `sec` before `cmp`. On the 6502, an instruction without an operand is also redundant if what it would change is known for certain to be that already (see above): e.g. `sec` after `cmp #10 : bcc less` (the carry is already set), or `tay` when A and Y are both 0 (and the flags already agree). A load of a constant that happens to equal the register isn't counted, since the constant may mean something else (e.g. `ldx #>handler`). This can point to a bug, or to code that was left behind. `config.set_redundant_instruction_comments(False)` turns it off.

It's only looked for within a straight run of code: a label, a branch, a call or the end of the run counts as reading everything.

On the 6502, only instructions that just change registers and flags can be redundant: loads, transfers, arithmetic and logic, compares, shifts of A, CLC, SEC and CLV. An instruction isn't redundant if it reads memory mapped I/O (see [`io_range()`](commands.md#io_range)), or reads an address that isn't known (an indirect load), or if code jumps into the middle of it (the BIT trick, e.g. `bit $02a9` skipping `lda #2`).

On the Z80, the same is done, e.g. `ld a,(hl)` just before `pop af`, or `scf` before `cp`. The instructions that can be redundant are: loads into registers (not `ld (hl),a` etc., nor `ld i,a` or `ld r,a`), INC and DEC of registers, arithmetic and logic, compares, rotates and shifts, BIT, RES and SET of registers, DAA, CPL, SCF, CCF, NEG and `ex de,hl`. IN isn't, nor is a read of memory mapped I/O; with any I/O named, a read through HL, BC, DE, IX or IY isn't either, since its address isn't known. A CALL, RST, jump or return (including `ret cc`) counts as reading everything.
