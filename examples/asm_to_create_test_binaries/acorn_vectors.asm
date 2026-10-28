; Code that sets the BBC Micro's OS vectors (at $0200-$0235) in the ways
; acorn.py recognises, for python/acorn_vectors.py. Assemble with:
;
;   acme -o ../orig/acorn_vectors.orig acorn_vectors.asm

    * = $2000

start
    ; A load and store for each byte, with X
    ldx #<irq2_handler
    stx $206
    ldx #>irq2_handler
    stx $207

    ; With Y, and the high byte first
    ldy #>wrch_handler
    sty $20f
    ldy #<wrch_handler
    sty $20e

    ; Two loads, then two stores
    ldx #<rdch_handler
    ldy #>rdch_handler
    stx $210
    sty $211

    ; Two loads, then two stores, the high byte first
    lda #<byte_handler
    ldx #>byte_handler
    stx $20b
    sta $20a

    ; Not a vector: the bytes stored aren't a pair
    lda #<start
    ldx #>start
    sta $206
    stx $209
    rts

irq2_handler
    rti

wrch_handler
    rts

rdch_handler
    rts

byte_handler
    rts
