; Test a move whose source ends exactly at the top of memory (&10000).
; The file is 32 bytes loaded at $ffe0. $fff0-$ffff is moved to $0900.

* = $ffe0

set_flag
    lda #1
    sta $70
    rts
    !fill $10 - 5, $ea

!pseudopc $0900 {
start
    jsr set_flag
    lda $70
    rts
    !fill $10 - 6, $ea
}
