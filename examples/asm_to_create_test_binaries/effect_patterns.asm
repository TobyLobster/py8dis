; Code for the effect patterns in python/effect_patterns.py, which match
; what code does (the values it stores, and the registers at a call) rather
; than the bytes of its instructions. Assemble with:
;
;   acme -o ../orig/effect_patterns.orig effect_patterns.asm

vector1 = $0300
vector2 = $0302
temp    = $70
flag    = $71

    * = $2000

start
    ; 1. A vector set in the other order, with an instruction between
    lda #<handler1
    ldx #>handler1
    sei
    stx vector1+1
    sta vector1
    cli

    ; 2. A vector set twice in one run
    lda #<handler2
    sta vector2
    lda #>handler2
    sta vector2+1
    lda #<handler3
    sta vector2
    lda #>handler3
    sta vector2+1

    ; 3. Half set: the call could change the high byte
    lda #$12
    sta vector1
    jsr subroutine

    ; 4. Half set: the high byte isn't known
    lda #$34
    sta vector2
    lda temp
    sta vector2+1

    ; 5. The value loaded into X and transferred to A
    ldx #<handler4
    txa
    sta vector1
    lda #>handler4
    sta vector1+1

    ; 6. A call with a value in memory and a register: matched
    lda #3
    sta temp
    ldx #5
    jsr print
    ; ...with X not 5: not matched
    lda #3
    sta temp
    ldx #6
    jsr print
    ; ...with a value in temp that isn't known: not matched
    lda flag
    sta temp
    ldx #5
    jsr print
    ; ...with flag stored too (any value)
    lda #7
    sta temp
    lda flag
    sta flag
    ldx #5
    jsr print

    ; 7. Split by a label: two half settings
    lda #<handler5
    sta vector2
    bne split
split
    lda #>handler5
    sta vector2+1
    rts

subroutine
    rts

print
    rts

handler1
    rti
handler2
    rti
handler3
    rti
handler4
    rti
handler5
    rti
