; What py8dis knows about the Z80's registers and flags (October 2026), for
; state_z80 (see its control file), which shows them after each instruction.
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/state_z80.orig state_z80.asm

    ORG $8000

start:
    ; Loads, arithmetic and the flags
    ld a,$7f
    inc a                           ; $80: S and P/V (overflow) set
    ld b,a
    add a,b                         ; $00, with the carry
    adc a,$10                       ; $11
    sub $12                         ; $ff, with a borrow
    neg                             ; $01
    ld c,$99
    ld a,c
    add a,1                         ; $9a
    daa                             ; $00 (decimal 99 + 1), with the carry
    xor a                           ; 0, whatever A was
    cpl                             ; $ff
    and $0f
    or $30
    cp $3f                          ; Z set, A unchanged
    scf
    ccf
    rlca
    sla a
    bit 7,a
    set 0,a
    res 1,a

    ; 16 bits, IX and IY, and their halves
    ld hl,$1234
    ld de,$1000
    add hl,de                       ; $2234
    or a
    sbc hl,de                       ; $1234 again
    ld ix,$4000
    ld iyl,$20
    inc ixh
    ld a,ixh
    ld sp,$ff00
    push af
    pop bc                          ; (B and C aren't known: memory isn't tracked)
    ld i,a
    ld a,i

    ; The alternate registers
    ld a,1
    ex af,af'
    ld a,2
    ex af,af'                       ; A is 1 again
    exx
    ld b,3
    exx

    ; What's known after a conditional jump isn't taken
    ld b,5
loop:
    djnz loop                       ; B is 0
    jr nz,skip                      ; Z is set
    jp c,skip                       ; the carry is clear
    ret m                           ; S is clear
    ldir                            ; BC is 0
    ld b,4
    otir                            ; B is 0
    in a,($fe)                      ; A isn't known
skip:
    ret
