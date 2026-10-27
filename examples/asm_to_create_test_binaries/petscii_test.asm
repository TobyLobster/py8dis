; PETSCII and screen code text, for config.set_text_encoding() and the string
; commands' encoding option (see python/petscii_test.py). Assemble with:
;
;   acme -o ../orig/petscii_test.orig petscii_test.asm

chrout = $ffd2
screen = $0400

    * = $c000

start
    lda #$93                    ; clear the screen
    jsr chrout
    ldx #0
print_loop
    lda message,x
    beq copy_title
    jsr chrout
    inx
    bne print_loop
copy_title
    ldx #title_end - title - 1
copy_loop
    lda title,x
    sta screen,x
    dex
    bpl copy_loop
    lda #$41                    ; PETSCII 'a' (an 'A' in the C64's default character set)
    jsr chrout
    rts

; PETSCII, with a control code, a quote, upper and lower case, and a return
message
    !byte $93
    !pet "Hello, World! Say ", $22, "hi", $22, 13, 0

; PETSCII with characters that aren't shown as text: pound, up arrow, left
; arrow and some graphics characters
symbols
    !pet "cost: "
    !byte $5c
    !pet "5 "
    !byte $5e, $5f, $60, $7b, $a0, $b0, $db, $ff
    !byte 0

; Screen codes, as copied to screen memory
title
    !scr "@ Score [000] Lives 3"
title_end

; An ASCII string, in a PETSCII disassembly
ascii_text
    !text "ASCII text", 0

; A string with its last character's top bit set
hi_string
    !pet "end"
    !byte 'x' + $80

; PETSCII text found by autostring()
found
    !pet "found by autostring", 0
