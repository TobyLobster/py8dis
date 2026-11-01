; A 6502 program for python/regex_snippets.py, whose regex snippets match
; its code using operands that used to be misread or refused: a one
; character operand, A for the accumulator, negative and binary immediate
; values, a branch's offset in hex, and spaces in an operand. Assemble with:
;
;   acme -o ../orig/regex_snippets.orig regex_snippets.asm
;
; (It isn't meant to do anything useful when run.)

* = $2000

start
    lda #$ff                ; 'lda #-1'
    sta 7                   ; 'sta 7'
    asl                     ; 'asl A'
    ldx #%00000101          ; 'ldx #%.....#.#'
    bne skip                ; 'bne $01'
    brk
skip
    lda message             ; 'lda n' (any address)
    sta $70,x               ; 'sta $70, x'
    rts

message
    !byte 1
