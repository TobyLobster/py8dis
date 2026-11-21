; Two banks of code that both run at $8000 (e.g. two banks of a cartridge,
; or two sideways ROMs), and the main program that calls them, for
; python/banks_test.py. The three parts are at $1000, $2000 and $3000 in the
; file (which starts at $1000), and the control file loads each part
; separately, so that there are gaps between them. Assemble with:
;
;   acme -o ../orig/banks_test.orig banks_test.asm

bank_select = $70

    * = $1000

main
    lda #0
    sta bank_select
    jsr $8000           ; (bank A's entry point)
    lda #1
    sta bank_select
    jsr $8000           ; (bank B's entry point)
    rts

    * = $2000

!pseudopc $8000 {
bank_a
    jsr a_print
    rts
a_print
    ldx #0
a_loop
    lda a_text,x
    beq a_done
    jsr $ffee
    inx
    bne a_loop
a_done
    rts
a_text
    !text "Bank A", 13, 0
}

    * = $3000

!pseudopc $8000 {
bank_b
    jmp b_start
b_text
    !text "Bank B", 13, 0
b_start
    ldx #0
b_loop                  ; (at $800d, the middle of an instruction in bank A)
    lda b_text,x
    beq b_done
    jsr $ffee
    inx
    bne b_loop
b_done
    rts
}
