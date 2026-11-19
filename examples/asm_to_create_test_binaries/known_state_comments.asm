; Comments from what's known about the registers and flags (November 2026),
; for known_state_comments (see its control file): code where what's known
; after a branch that isn't taken is worth a comment.
; Assemble with: acme -o ../orig/known_state_comments.orig known_state_comments.asm

    * = $2000

start
    ; 1. After a CMP and a BNE that isn't taken, the values were equal, so
    ;    carry is set, and ADC #3 adds 4
    lda $70
    cmp $71
    bne different
    adc #3                  ; Carry is set, so add 4
    sta $72

    ; 2. After INY and a BNE that isn't taken, Y is 0, so TYA makes A 0
    ldy $73
-
    iny
    bne -
    tya                     ; A=0
    sta $74

    ; 3. After a BCC that isn't taken, carry is set: ROR rotates a set bit
    ;    into bit 7, and ROL rotates it out again, setting carry (which the
    ;    ROL of memory relies on: a bit shifted out is only commented if
    ;    something reads the carry afterwards)
    lda $75
    bcc different
    ror                     ; rotate in a set bit
    rol                     ; rotate set bit out (sets carry)
    sta $76
    rol $82                 ; rotate in a set bit
    rts

    ; The rest is what's known bit by bit (see knownbits.py)
bits

    ; 4. AND #$3f clears the top two bits, so the second ASL shifts out a
    ;    clear bit, and ADC #4 needs no CLC (the first ASL's carry isn't
    ;    used, so it gets no comment)
    lda $77
    and #$3f
    asl
    asl                     ; shift clear bit out (clears carry)
    adc #4
    sta $78

    ; 5. ORA #$80 sets bit 7, so BMI always branches
    lda $79
    ora #$80
    bmi +                   ; ALWAYS branch
+

    ; 6. After AND #1 and a BEQ that isn't taken, A is 1
    lda $7a
    and #1
    beq different
    tax                     ; X=1

    ; 7. After a BPL that isn't taken, bit 7 of A is set, so ASL sets carry
    ;    (which is used, by the ROL)
    lda $7b
    bpl different
    asl                     ; shift set bit out (sets carry)
    rol $7c                 ; rotate in a set bit

    ; 8. A is at most $0f after AND #$0f, so it's less than $10: BCC always
    ;    branches
    lda $7d
    and #$0f
    cmp #$10
    bcc +                   ; ALWAYS branch
+

    ; 9. SEC then ROR of memory puts a set bit in bit 7, so BMI always
    ;    branches; and LSR always clears bit 7, so BPL always branches
    sec
    ror $7e                 ; rotate in a set bit
    bmi +                   ; ALWAYS branch
+
    lda $7f
    lsr
    bpl +                   ; ALWAYS branch
+

    ; 10. With D clear (binary arithmetic), A is at most $0f + $f0 = $ff, so
    ;     ADC doesn't carry: BCC always branches
    cld
    lda $80
    and #$0f
    clc
    adc #$f0
    bcc +                   ; ALWAYS branch
+

    ; 11. A compare with A unknown leaves carry unknown ('pending'), so ROR
    ;     rotates in an unknown bit, and nothing is known about A or X
    lda $81
    cmp #7
    ror
    tax
    rts

different
    rts
