; A 6502 program for python/copy_loops.py: loops that copy memory, or set
; it, whose comments (from the built in snippets, see py8dis/snippets6502.py)
; used to give the wrong first byte or number of bytes. Assemble with:
;
;   acme -o ../orig/copy_loops.orig copy_loops.asm
;
; (It isn't meant to do anything useful when run.)

* = $2000

start
    ; 1. X counted down to zero from 0: the 256 bytes from $3000 (not from $3001)
    ldx #0
loop1
    lda $3000,x
    sta $3100,x
    dex
    bne loop1

    ; 2. Y counted down past zero from 130: just the byte at $3200+130
    ldy #130
loop2
    lda $3200,y
    sta $3300,y
    dey
    bpl loop2

    ; 3. Y counted down from 9 to 2: the 8 bytes from $3402 (the control file
    ; gives the load's operand an expression)
    ldy #9
loop3
    lda $3400,y
    sta $3500,y
    dey
    cpy #2
    bcs loop3

    ; 4. X counted down to 4, but from below it: just the byte at $3601
    ldx #1
loop4
    lda $3600,x
    sta $3700,x
    dex
    cpx #4
    bcs loop4

    ; 5. X counted up from $f0 to $10, wrapping round: not one run of bytes,
    ; so not commented
    ldx #$f0
loop5
    lda $3800,x
    sta $3900,x
    inx
    cpx #$10
    bne loop5

    ; 6. Y counted up from $80 until it wraps round to 0: the 128 bytes from
    ; $3a80
    ldy #$80
loop6
    lda $3a00,y
    sta $3b00,y
    iny
    cpy #0
    bne loop6

    ; 7. X counted up from 2 while below 8 (BCC): the 6 bytes from $3c02 (the
    ; control file gives the store's operand an expression)
    ldx #2
loop7
    lda $3c00,x
    sta $3d00,x
    inx
    cpx #8
    bcc loop7

    ; 8. Clearing 256 bytes (X counted down from 0) at $3e00+Y, after a load
    ; of Y from memory
    lda #0
    ldy $3f00
    ldx #0
loop8
    sta $3e00,y
    iny
    dex
    bne loop8

    ; 9. Setting 4 bytes at $3f80+Y to $ff, after a load of Y from zero page
    lda #$ff
    ldy $70
    ldx #4
loop9
    sta $3f80,y
    iny
    dex
    bne loop9
    rts
