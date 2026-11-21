; Every documented Z80 instruction (October 2026), for testing py8dis.
; Assemble with: z88dk-z80asm -mz80 -b -o../orig/test_z80.orig test_z80.asm

    ORG $8000

start:

; 8 bit loads

    ld b,b
    ld b,c
    ld b,d
    ld b,e
    ld b,h
    ld b,l
    ld b,a
    ld c,b
    ld c,c
    ld c,d
    ld c,e
    ld c,h
    ld c,l
    ld c,a
    ld d,b
    ld d,c
    ld d,d
    ld d,e
    ld d,h
    ld d,l
    ld d,a
    ld e,b
    ld e,c
    ld e,d
    ld e,e
    ld e,h
    ld e,l
    ld e,a
    ld h,b
    ld h,c
    ld h,d
    ld h,e
    ld h,h
    ld h,l
    ld h,a
    ld l,b
    ld l,c
    ld l,d
    ld l,e
    ld l,h
    ld l,l
    ld l,a
    ld a,b
    ld a,c
    ld a,d
    ld a,e
    ld a,h
    ld a,l
    ld a,a
    ld b,$11
    ld c,$22
    ld d,$33
    ld e,$44
    ld h,$55
    ld l,$66
    ld a,$77
    ld b,(hl)
    ld c,(hl)
    ld d,(hl)
    ld e,(hl)
    ld h,(hl)
    ld l,(hl)
    ld a,(hl)
    ld (hl),b
    ld (hl),c
    ld (hl),d
    ld (hl),e
    ld (hl),h
    ld (hl),l
    ld (hl),a
    ld (hl),$5a
    ld b,(ix+0)
    ld c,(ix+5)
    ld d,(ix-1)
    ld e,(ix+127)
    ld h,(ix-128)
    ld l,(ix+0)
    ld a,(ix+5)
    ld (ix+5),b
    ld (ix-1),c
    ld (ix+127),d
    ld (ix-128),e
    ld (ix+0),h
    ld (ix+5),l
    ld (ix-1),a
    ld (ix+2),$a5
    ld b,(iy+3)
    ld c,(iy-3)
    ld d,(iy+64)
    ld e,(iy+3)
    ld h,(iy-3)
    ld l,(iy+64)
    ld a,(iy+3)
    ld (iy-3),b
    ld (iy+64),c
    ld (iy+3),d
    ld (iy-3),e
    ld (iy+64),h
    ld (iy+3),l
    ld (iy-3),a
    ld (iy+2),$a5
    ld a,(bc)
    ld a,(de)
    ld a,(value)
    ld (bc),a
    ld (de),a
    ld (value),a
    ld a,i
    ld a,r
    ld i,a
    ld r,a

; 16 bit loads

    ld bc,$1234
    ld de,value
    ld hl,table
    ld sp,$ff00
    ld ix,table
    ld iy,$4000
    ld hl,(word)
    ld bc,(word)
    ld de,(word)
    ld sp,(word)
    ld ix,(word)
    ld iy,(word)
    ld (word),hl
    ld (word),bc
    ld (word),de
    ld (word),sp
    ld (word),ix
    ld (word),iy
    ld sp,hl
    ld sp,ix
    ld sp,iy
    push bc
    push de
    push hl
    push af
    push ix
    push iy
    pop bc
    pop de
    pop hl
    pop af
    pop ix
    pop iy

; Exchanges, block transfers and searches

    ex de,hl
    ex af,af'
    exx
    ex (sp),hl
    ex (sp),ix
    ex (sp),iy
    ldi
    ldir
    ldd
    lddr
    cpi
    cpir
    cpd
    cpdr

; 8 bit arithmetic and logic

    add a,b
    add a,c
    add a,d
    add a,e
    add a,h
    add a,l
    add a,a
    add a,(hl)
    add a,$0f
    add a,(ix+4)
    add a,(iy-4)
    adc a,b
    adc a,c
    adc a,d
    adc a,e
    adc a,h
    adc a,l
    adc a,a
    adc a,(hl)
    adc a,$0f
    adc a,(ix+4)
    adc a,(iy-4)
    sub b
    sub c
    sub d
    sub e
    sub h
    sub l
    sub a
    sub (hl)
    sub $0f
    sub (ix+4)
    sub (iy-4)
    sbc a,b
    sbc a,c
    sbc a,d
    sbc a,e
    sbc a,h
    sbc a,l
    sbc a,a
    sbc a,(hl)
    sbc a,$0f
    sbc a,(ix+4)
    sbc a,(iy-4)
    and b
    and c
    and d
    and e
    and h
    and l
    and a
    and (hl)
    and $0f
    and (ix+4)
    and (iy-4)
    xor b
    xor c
    xor d
    xor e
    xor h
    xor l
    xor a
    xor (hl)
    xor $0f
    xor (ix+4)
    xor (iy-4)
    or b
    or c
    or d
    or e
    or h
    or l
    or a
    or (hl)
    or $0f
    or (ix+4)
    or (iy-4)
    cp b
    cp c
    cp d
    cp e
    cp h
    cp l
    cp a
    cp (hl)
    cp $0f
    cp (ix+4)
    cp (iy-4)
    inc b
    inc c
    inc d
    inc e
    inc h
    inc l
    inc a
    inc (hl)
    inc (ix+1)
    inc (iy-1)
    dec b
    dec c
    dec d
    dec e
    dec h
    dec l
    dec a
    dec (hl)
    dec (ix+1)
    dec (iy-1)

; General purpose arithmetic and CPU control

    daa
    cpl
    neg
    ccf
    scf
    nop
    halt
    di
    ei
    im 0
    im 1
    im 2

; 16 bit arithmetic

    add hl,bc
    add hl,de
    add hl,hl
    add hl,sp
    add ix,bc
    add ix,de
    add ix,ix
    add ix,sp
    add iy,bc
    add iy,de
    add iy,iy
    add iy,sp
    adc hl,bc
    adc hl,de
    adc hl,hl
    adc hl,sp
    sbc hl,bc
    sbc hl,de
    sbc hl,hl
    sbc hl,sp
    inc bc
    inc de
    inc hl
    inc sp
    inc ix
    inc iy
    dec bc
    dec de
    dec hl
    dec sp
    dec ix
    dec iy

; Rotates and shifts

    rlca
    rla
    rrca
    rra
    rld
    rrd
    rlc b
    rlc c
    rlc d
    rlc e
    rlc h
    rlc l
    rlc a
    rlc (hl)
    rlc (ix+7)
    rlc (iy-7)
    rl b
    rl c
    rl d
    rl e
    rl h
    rl l
    rl a
    rl (hl)
    rl (ix+7)
    rl (iy-7)
    rrc b
    rrc c
    rrc d
    rrc e
    rrc h
    rrc l
    rrc a
    rrc (hl)
    rrc (ix+7)
    rrc (iy-7)
    rr b
    rr c
    rr d
    rr e
    rr h
    rr l
    rr a
    rr (hl)
    rr (ix+7)
    rr (iy-7)
    sla b
    sla c
    sla d
    sla e
    sla h
    sla l
    sla a
    sla (hl)
    sla (ix+7)
    sla (iy-7)
    sra b
    sra c
    sra d
    sra e
    sra h
    sra l
    sra a
    sra (hl)
    sra (ix+7)
    sra (iy-7)
    srl b
    srl c
    srl d
    srl e
    srl h
    srl l
    srl a
    srl (hl)
    srl (ix+7)
    srl (iy-7)

; Bit set, reset and test

    bit 0,b
    bit 0,c
    bit 0,d
    bit 0,e
    bit 0,h
    bit 0,l
    bit 0,a
    bit 0,(hl)
    bit 0,(ix+0)
    bit 0,(iy-1)
    bit 1,b
    bit 1,c
    bit 1,d
    bit 1,e
    bit 1,h
    bit 1,l
    bit 1,a
    bit 1,(hl)
    bit 1,(ix+1)
    bit 1,(iy-2)
    bit 2,b
    bit 2,c
    bit 2,d
    bit 2,e
    bit 2,h
    bit 2,l
    bit 2,a
    bit 2,(hl)
    bit 2,(ix+2)
    bit 2,(iy-3)
    bit 3,b
    bit 3,c
    bit 3,d
    bit 3,e
    bit 3,h
    bit 3,l
    bit 3,a
    bit 3,(hl)
    bit 3,(ix+3)
    bit 3,(iy-4)
    bit 4,b
    bit 4,c
    bit 4,d
    bit 4,e
    bit 4,h
    bit 4,l
    bit 4,a
    bit 4,(hl)
    bit 4,(ix+4)
    bit 4,(iy-5)
    bit 5,b
    bit 5,c
    bit 5,d
    bit 5,e
    bit 5,h
    bit 5,l
    bit 5,a
    bit 5,(hl)
    bit 5,(ix+5)
    bit 5,(iy-6)
    bit 6,b
    bit 6,c
    bit 6,d
    bit 6,e
    bit 6,h
    bit 6,l
    bit 6,a
    bit 6,(hl)
    bit 6,(ix+6)
    bit 6,(iy-7)
    bit 7,b
    bit 7,c
    bit 7,d
    bit 7,e
    bit 7,h
    bit 7,l
    bit 7,a
    bit 7,(hl)
    bit 7,(ix+7)
    bit 7,(iy-8)
    set 0,b
    set 0,c
    set 0,d
    set 0,e
    set 0,h
    set 0,l
    set 0,a
    set 0,(hl)
    set 0,(ix+0)
    set 0,(iy-1)
    set 1,b
    set 1,c
    set 1,d
    set 1,e
    set 1,h
    set 1,l
    set 1,a
    set 1,(hl)
    set 1,(ix+1)
    set 1,(iy-2)
    set 2,b
    set 2,c
    set 2,d
    set 2,e
    set 2,h
    set 2,l
    set 2,a
    set 2,(hl)
    set 2,(ix+2)
    set 2,(iy-3)
    set 3,b
    set 3,c
    set 3,d
    set 3,e
    set 3,h
    set 3,l
    set 3,a
    set 3,(hl)
    set 3,(ix+3)
    set 3,(iy-4)
    set 4,b
    set 4,c
    set 4,d
    set 4,e
    set 4,h
    set 4,l
    set 4,a
    set 4,(hl)
    set 4,(ix+4)
    set 4,(iy-5)
    set 5,b
    set 5,c
    set 5,d
    set 5,e
    set 5,h
    set 5,l
    set 5,a
    set 5,(hl)
    set 5,(ix+5)
    set 5,(iy-6)
    set 6,b
    set 6,c
    set 6,d
    set 6,e
    set 6,h
    set 6,l
    set 6,a
    set 6,(hl)
    set 6,(ix+6)
    set 6,(iy-7)
    set 7,b
    set 7,c
    set 7,d
    set 7,e
    set 7,h
    set 7,l
    set 7,a
    set 7,(hl)
    set 7,(ix+7)
    set 7,(iy-8)
    res 0,b
    res 0,c
    res 0,d
    res 0,e
    res 0,h
    res 0,l
    res 0,a
    res 0,(hl)
    res 0,(ix+0)
    res 0,(iy-1)
    res 1,b
    res 1,c
    res 1,d
    res 1,e
    res 1,h
    res 1,l
    res 1,a
    res 1,(hl)
    res 1,(ix+1)
    res 1,(iy-2)
    res 2,b
    res 2,c
    res 2,d
    res 2,e
    res 2,h
    res 2,l
    res 2,a
    res 2,(hl)
    res 2,(ix+2)
    res 2,(iy-3)
    res 3,b
    res 3,c
    res 3,d
    res 3,e
    res 3,h
    res 3,l
    res 3,a
    res 3,(hl)
    res 3,(ix+3)
    res 3,(iy-4)
    res 4,b
    res 4,c
    res 4,d
    res 4,e
    res 4,h
    res 4,l
    res 4,a
    res 4,(hl)
    res 4,(ix+4)
    res 4,(iy-5)
    res 5,b
    res 5,c
    res 5,d
    res 5,e
    res 5,h
    res 5,l
    res 5,a
    res 5,(hl)
    res 5,(ix+5)
    res 5,(iy-6)
    res 6,b
    res 6,c
    res 6,d
    res 6,e
    res 6,h
    res 6,l
    res 6,a
    res 6,(hl)
    res 6,(ix+6)
    res 6,(iy-7)
    res 7,b
    res 7,c
    res 7,d
    res 7,e
    res 7,h
    res 7,l
    res 7,a
    res 7,(hl)
    res 7,(ix+7)
    res 7,(iy-8)

; Input and output

    in a,($fe)
    out ($fe),a
    in b,(c)
    in c,(c)
    in d,(c)
    in e,(c)
    in h,(c)
    in l,(c)
    in a,(c)
    out (c),b
    out (c),c
    out (c),d
    out (c),e
    out (c),h
    out (c),l
    out (c),a
    ini
    inir
    ind
    indr
    outi
    otir
    outd
    otdr

; Jumps, calls and returns

loop:
    jp nz,loop
    jp z,loop
    jp nc,loop
    jp c,loop
    jp po,loop
    jp pe,loop
    jp p,loop
    jp m,loop
    jr nz,loop
    jr z,loop
    jr nc,loop
    jr c,loop
    djnz loop
    call nz,subroutine
    call z,subroutine
    call nc,subroutine
    call c,subroutine
    call po,subroutine
    call pe,subroutine
    call p,subroutine
    call m,subroutine
    call subroutine
    rst $00
    rst $08
    rst $10
    rst $18
    rst $20
    rst $28
    rst $30
    rst $38
    jr forward
    db $ff
forward:
    jp finish

subroutine:
    ret nz
    ret z
    ret nc
    ret c
    ret po
    ret pe
    ret p
    ret m
    ret

interrupt:
    reti

nmi:
    retn

finish:
    jp (hl)

jump_ix:
    jp (ix)

jump_iy:
    jp (iy)

value:
    db $42
word:
    dw $1234
table:
    db 1, 2, 3, 4
