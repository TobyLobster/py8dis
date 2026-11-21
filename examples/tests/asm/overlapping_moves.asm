; A 6502 program for python/overlapping_moves.py, laid out like the game
; Revs (Geoff Crammond, 1984), scaled down: six blocks that an unpacker
; moves elsewhere to run, in the same pattern as Revs's. The program is at
; $1000-$15ff (Revs: &1200-&6fff), and the blocks are:
;
;   A $1000-$103f, runs at $1a00 (above the program)
;   D $1040-$107f, runs at $0c00 (below it)
;   C $1080-$10af, runs at $1900 (above it)
;   B $1300-$133f, runs at $1880 (above it)
;   E $1400-$14ff, runs at $0fe0, over the start of the program, where A, D
;     and C were, and some of the rest
;   F $1540-$15ff, runs at $14c0, over the end of E, some of the rest, and
;     its own start
;
; Assemble with:
;
;   acme -o ../orig/overlapping_moves.orig overlapping_moves.asm
;
; (It isn't meant to do anything useful when run.)

* = $1000

; A
!pseudopc $1a00 {
a_entry
    jsr d_entry
    jsr c_entry
    rts
    !fill $40 - (* - a_entry), $aa
}

; D
!pseudopc $0c00 {
d_entry
    lda #1
    sta $70
    rts
    !fill $40 - (* - d_entry), $dd
}

; C
!pseudopc $1900 {
c_entry
    lda b_data
    rts
    !fill $30 - (* - c_entry), $cc
}

; The rest of the program, which isn't moved
    !fill $1100 - *, 0
start
    jsr a_entry
    jsr e_entry
    jsr f_entry
    rts
    !fill $1300 - *, 0

; B
!pseudopc $1880 {
b_data
    !byte 1, 2, 3, 4, 5, 6, 7, 8
    !fill $40 - (* - b_data), $bb
}

    !fill $1400 - *, 0

; E
!pseudopc $0fe0 {
e_entry
    ldx #3
    lda f_table,x
    rts
    !fill $100 - (* - e_entry), $ee
}

    !fill $1540 - *, 0

; F
!pseudopc $14c0 {
f_entry
    rts
f_table
    !byte $10, $20, $30, $40
    !fill $c0 - (* - f_entry), $ff
}
