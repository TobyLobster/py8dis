; Comments on where known registers are used (November 2026), for
; register_use_comments (see its control file). Assemble with:
;
;   acme -o ../orig/register_use_comments.orig register_use_comments.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr index_far_back
    jsr clear_count_up
    jsr set_count_down
    jsr clear_to_zero
    jsr clear_indirect
    jsr self_modified
    rts

; 1. Y is set well before it's used as the offset, so the STA says what it
;    is ('Offset Y=$11'); the LDA just after 'ldy #0' doesn't need it
index_far_back
    ldy #$11
    lda $70
    clc
    adc $71
    sta $72
    lda #1
    sta ($74),y             ; Offset Y=$11
    ldy #0
    lda ($74),y
    rts

; 2. A memory set loop counting Y up to a limit: A is 0 each time round, so
;    the STA says so, and the loop clears 16 bytes from table1
clear_count_up
    ldy #0
    tya
-
    sta table1,y            ; A=0
    iny
    cpy #16
    bne -
    rts

; 3. Counting X down past zero: 8 bytes from table2 set to 255
set_count_down
    lda #$ff
    ldx #7
-
    sta table2,x            ; A=$ff
    dex
    bpl -
    rts

; 4. Counting Y down to zero: the bytes are table3+1 to table3+4
clear_to_zero
    lda #0
    ldy #4
-
    sta table3,y            ; A=0
    dey
    bne -
    rts

; 5. Through a pointer: 256 bytes from the address in $74
clear_indirect
    lda #0
    tay
-
    sta ($74),y             ; A=0
    iny
    bne -
    rts

; 6. Code changes the LDX's operand, so X isn't known after it
self_modified
    lda $76
    sta modified+1
modified
    ldx #0
    txa
    rts

table1
    !fill 16, $11
table2
    !fill 8, $22
table3
    !fill 5, $33
