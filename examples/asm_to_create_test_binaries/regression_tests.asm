; Regression tests for py8dis bugs fixed in October 2026.
;
; The binary is split into two files at $2080 (see 'go') so that the control
; file can test calling entry() before a second load().

* = $2000

start
    ; subroutine() decoration: on_entry 'y' is private "(ignored)" so 'ldy #3'
    ; should get no comment. on_exit has no entry for X, which used to crash
    ; with a KeyError when X is used after the call.
    ldy #3
    lda #7
    jsr store_value
    stx $71
    sty $72

    ; subroutine(..., hook=False) should not decorate this call
    jsr quiet_routine

    ; AND (zp,X) changes A but not the carry
    lda #5
    sec
    and ($70,x)
    tay                     ; must not be commented 'Y=5'
    adc #1                  ; carry is still set

    ; AND #$ff with A unknown leaves Z unknown (not set by the LDX)
    lda $70
    ldx #0
    and #$ff
    beq +                   ; must not be 'ALWAYS branch'

    ; ORA #1 with A unknown leaves N unknown (not set by the LDX)
    lda $70
    ldx #$80
    ora #1
    bmi +                   ; must not be 'ALWAYS branch'

    ; Carry is 'pending' (unknown) after a compare, so ROR A gives an unknown result
    lda #5
    cmp #7
    ror
    tax                     ; must not be commented 'X=&82'
+
    jmp part2

store_value
    sta $70
    ldx #0
    ldy #1
    rts

quiet_routine
    rts

    ; Not called: a snippet whose pattern has '.' (any instruction) for the
    ; cpx #4 finds it (see the control file). The wildcard used not to match
    ; cpx #n, so this was left as data.
wildcard_snippet
    ldy #3
    cpx #4
    sta $73
    rts

    ; The same snippet matches from the second byte of 'bit $03a0' (a0 03 e0
    ; 04 85 73). That used to be traced as code too, overlapping the BIT. It
    ; starts in the middle of an instruction, so it's now ignored (the control
    ; file makes this an entry point).
mid_instruction_snippet
    bit $03a0
    cpx #4
    sta $73
    rts

    !fill $2080 - *, $ea

; ---------------------------------------------------------------------------
; Second file, loaded separately at $2080
part2
    jsr store_value
    rts

empty_string        ; stringn() with a zero length used to fail
    !byte 0
rts_table           ; rts_code_ptr() with &ffff (i.e. code at &0000) used to fail
    !word $ffff
rts_table_high      ; ...and with the low and high bytes stored separately (high first)
    !byte $ff
rts_table_low
    !byte $ff
unterminated        ; stringhi() reaching the end of the data without a terminator used to crash
    !text "END"
