; Test a move whose destination ends exactly at the top of memory (&10000).
; The file is 32 bytes loaded at $2000. $2010-$201f is moved to $fff0-$ffff.

* = $2000

start
    jsr set_flag
    lda $70
    rts
    !fill $10 - 6, $ea

!pseudopc $fff0 {
set_flag
    lda #1
    sta $70
    rts
    !fill $10 - 5, $ea
}
