; What subroutines leave behind (November 2026), for subroutine_summaries
; (see its control file): what's known after a JSR, from what the subroutine
; doesn't change and what's known at all its returns, and its 'On Exit'
; notes for what callers rely on. Assemble with:
;
;   acme -o ../orig/subroutine_summaries.orig subroutine_summaries.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    ; 1. clear_carry always returns with the carry clear, and doesn't change
    ;    X: so X is still 4 after the call, and the BCC always branches.
    ;    Its 'On Exit' notes say both (the code after the call uses both),
    ;    but not that it leaves Y alone, since nothing uses that
    ldx #4
    ldy #6
    jsr clear_carry
    stx $70                 ; X=4
    bcc +                   ; ALWAYS branch
+
    ; 2. get_flag returns with A 0 or $80 (from both returns), so after it
    ;    the low bits of A are known: AND #$7f gives 0
    jsr get_flag
    and #$7f                ; A=0
    sta $71

    ; 3. tail_call jumps to clear_carry, so what it leaves is what that
    ;    leaves: the carry is clear after it too
    jsr tail_call
    bcc +                   ; ALWAYS branch
+
    ; 4. drop_return throws its return address away (PLA : PLA), so a call
    ;    to it doesn't return here: nothing is known after it
    ldx #9
    jsr calls_drop_return
    stx $72                 ; (X isn't known)
    rts

clear_carry
    lda $73
    beq +
    clc
    rts
+
    clc
    rts

get_flag
    lda $74
    bmi +
    lda #0
    rts
+
    lda #$80
    rts

tail_call
    ldy #1
    jmp clear_carry

calls_drop_return
    jsr drop_return
    ldx #2
    rts

drop_return
    pla
    pla
    rts
