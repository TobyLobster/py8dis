; The Z80's undocumented opcodes (October 2026), for testing py8dis, which
; traces them as what they do.
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/undocumented_z80.orig undocumented_z80.asm
;
; z88dk-z80asm assembles some of them, written as below:

    ORG $8000

start:
    ; The halves of IX and IY
    ld ixh,a
    ld ixl,$12
    ld a,iyh
    ld b,iyl
    ld ixh,ixl
    ld iyl,iyh
    inc ixh
    dec iyl
    add a,ixl
    adc a,iyh
    sub ixh
    sbc a,iyl
    and ixl
    xor iyh
    or ixh
    cp iyl

    ; SLL (also called SLI or SL1): shift left, setting bit 0
    sll b
    sll a
    sll (hl)
    sll (ix+3)
    sll (iy-3)

    ; The indexed rotates, shifts, SET and RES that also copy the result to
    ; a register
    rlc (ix+2),b
    rr (iy-2),c
    sll (ix+1),d
    srl (iy+0),a
    set 3,(iy+1),a
    res 0,(ix-1),l

    ; Input to the flags only, and output of 0
    in f,(c)
    out (c),0

; The rest aren't accepted by z88dk-z80asm, and are written as bytes:

    ; The duplicates, e.g. ED 4C, which is another NEG
    db $ed, $4c                     ; neg
    db $ed, $4e                     ; im 0
    db $ed, $76                     ; im 1
    db $ed, $7e                     ; im 2
    db $ed, $63                     ; ld (word),hl
    dw word
    db $ed, $6b                     ; ld hl,(word)
    dw word
    db $dd, $cb, $05, $41           ; bit 0,(ix+5)
    db $fd, $cb, $fe, $7f           ; bit 7,(iy-2)

    ; ED opcodes that do nothing
    db $ed, $00
    db $ed, $77
    db $ed, $ff

    ; DD or FD before an instruction that doesn't use HL: the prefix does
    ; nothing
    db $dd, $3e, $05                ; ld a,5
    db $fd, $dd, $21, $34, $12      ; ld ix,$1234
    db $dd, $ed, $44                ; neg
    db $fd, $c3                     ; jp finish
    dw finish

    db 0, 0                         ; (not traced)

finish:
    db $ed, $55                     ; retn (another)

word:
    dw $1234
