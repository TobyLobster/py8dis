; A small program in a Commodore PRG file, loaded by load_prg() in
; python/prg_test.py (and p00_test.py and load_offset.py).
;
; Assemble with:   acme -f cbm -o ../orig/prg_test.orig prg_test.asm
; (the cbm format writes the two-byte load address before the data)

chrout = $ffd2

    * = $0801

    ; The BASIC program 10 SYS2061, which runs the machine code
    !word basic_end
    !word 10
    !byte $9e
    !text "2061"
    !byte 0
basic_end
    !word 0

start                           ; $080d = 2061
    ldx #0
loop
    lda message,x
    beq done
    jsr chrout
    inx
    bne loop
done
    rts

message
    !text "HELLO", 13, 0
