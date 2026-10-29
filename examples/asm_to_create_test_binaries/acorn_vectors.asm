; Code that sets the BBC Micro's OS vectors (at $0200-$0235) in the ways
; acorn.py recognises (any way that stores known values to both bytes), for
; python/acorn_vectors.py. Assemble with:
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

    ; Two loads, then another instruction, then the stores
    lda #<event_handler
    ldx #>event_handler
    sei
    sta $220
    stx $221
    cli

    ; Two vectors set together, sharing a high byte
    lda #<osword_handler
    sta $20c
    lda #<cli_handler
    sta $208
    lda #>osword_handler
    sta $20d
    sta $209

    ; The value loaded into X and transferred to A
    ldx #<user_handler
    txa
    sta $200
    lda #>user_handler
    sta $201

    ; Three loads, then the stores
    lda #<brk_handler
    ldx #>brk_handler
    ldy #0
    sta $202
    stx $203
    sty $70

    ; Not a vector: the bytes stored aren't a pair, so each is a vector
    ; with only one byte set (IRQ2V's low byte and CLIV's high byte)
    lda #<start
    ldx #>start
    sta $206
    stx $209

    ; The high byte isn't known: only the low byte is set to a known value
    lda #<start
    sta $212
    lda $70
    sta $213
    rts

irq2_handler
    rti

wrch_handler
    rts

rdch_handler
    rts

byte_handler
    rts

event_handler
    rts

osword_handler
    rts

cli_handler
    rts

user_handler
    rts

brk_handler
    rti
