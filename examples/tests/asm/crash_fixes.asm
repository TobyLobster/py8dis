; A 6502 program for python/crash_fixes.py, with things that used to stop
; py8dis with an error of its own (a Python exception): a split asked for
; inside an instruction and inside a word, an RTS for substitute_constants(),
; two banks at $8000 whose address the control file gives an expression
; with expr_label(), and a table entry (a name, then an address high byte
; first) that the control file reads with stringhi() and
; get_u16_be_binary(). Assemble with:
;
;   acme -o ../orig/crash_fixes.orig crash_fixes.asm
;
; (It isn't meant to do anything useful when run.)

* = $2000

start
    lda #1                  ; the control file asks for a split at $2001
    jsr get_value
    sta $70
    lda $8000               ; the first byte of whichever bank is in
    lda word_table
    rts

get_value
    lda #3                  ; named before the RTS (substitute_constants())
    rts

word_table
    !word $1234, $5678      ; the control file asks for a split at its second byte

; Two banks of data, which both run at $8000 (the control file moves them)
bank_a
    !byte 1, 2, 3, 4
bank_b
    !byte 5, 6, 7, 8

; A name ending with a byte with bit 7 set, then the address of 'start',
; high byte first
name
    !text "G", 'O' | $80
    !byte >start, <start
