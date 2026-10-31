; Redundant Z80 instructions (October 2026), for redundant_z80 (see its
; control file): py8dis comments an instruction whose results (registers and
; flags) are all changed again before anything uses them, '; Redundant
; instruction?'.
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/redundant_z80.orig redundant_z80.asm

    ORG $8000

start:
    ld a,(hl)               ; redundant: POP AF overwrites A and the flags
    pop af
    ld b,1                  ; redundant: so is the INC B that uses it, since
    inc b                   ; LD BC,nn overwrites B
    ld bc,$1234
    scf                     ; redundant: SCF again
    scf                     ; redundant: CP sets the carry
    cp (ix+3)               ; redundant: the same compare again
    cp (ix+3)
    jr nz,skip              ; (the flags are used here)
    ld a,1                  ; not redundant: the store uses A
    ld (hl),a
    ld e,2                  ; not redundant: OUT (C),E uses E
    out (c),e
    ld a,$7f                ; not redundant: IN A,(n) uses A (the port's high byte)
    in a,($fe)
    ld d,3                  ; not redundant: the subroutine could use D
    call skip
    ld d,4
    xor a                   ; redundant: LD A,5 overwrites A, and SUB B the flags
    ld a,5
    sub b
    ld h,6                  ; not redundant: PUSH HL uses H
    push hl
    ret z                   ; (a return could use anything)
    ld l,7                  ; redundant: RES 0,L would use it, but LD HL,nn
    res 0,l                 ; overwrites L (so RES 0,L is redundant too)
    ld hl,$4000
    set 3,(hl)              ; not redundant: it writes memory
    ld (ix+0),e
skip:
    ret
