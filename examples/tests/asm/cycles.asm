; Test cycle counts for branches (shown with config.set_show_cycles(True)).
; A taken branch takes an extra cycle if the target is in a different page to
; the *next* instruction.

* = $20f0

start
    ldx #3
    !fill $20fe - *, $ea
    dex
    ; The branch opcode is at $20ff but its operand is at $2100, and the target
    ; is in the same page as the next instruction ($2101): 2/3 cycles, not 2/4.
    bne +
+
    jsr moved_code
    rts

; Moved to $30fe at runtime. The branch at $30fe has its next instruction at
; $3100 and its target at $3102, in the same page: 2/3 cycles, not 2/4.
!pseudopc $30fe {
moved_code
    bne ++
    nop
    nop
++
    rts
}
