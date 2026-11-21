; A BBC Micro program for python/beebasm_moves.py: a block of code stored at
; $a000 that runs at $4010, over the end of the program at $4000. beebasm
; assembles a moved block at its runtime address, so it first copies the
; output in the way somewhere else: only the 16 bytes from $4010, not
; everything from $4010 up to $a000, for which there isn't room. The control
; file loads the two parts separately, so the bytes between them are zeros.
; Assemble with:
;
;   acme -o ../orig/beebasm_moves.orig beebasm_moves.asm
;
; (It isn't meant to do anything useful when run.)

* = $4000

start
    ldx #15
copy_loop
    lda block,x
    sta runs_at,x
    dex
    bpl copy_loop
    jmp runs_at
    !fill $4010 - *, $ea    ; (NOPs, as padding)
runs_at_in_program
    !fill 16, $ea           ; (what the block is copied over)

    !fill $a000 - *, 0

block
!pseudopc $4010 {
runs_at
    lda #'A'
    jsr $ffee
    lda #'B'
    jsr $ffee
    lda #'C'
    jsr $ffee
    rts
}
    !fill 16 - (* - block), 0
