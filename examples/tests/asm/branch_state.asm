; What's known about the registers after a BNE that isn't taken (October
; 2026), for branch_state (see its control file), which shows the CPU state
; after each instruction: Z is set, so the result that set it was 0, or the
; register compared was equal to the value.
; Assemble with: acme -o ../orig/branch_state.orig branch_state.asm

    * = $2000

start
    ldy #8
loop
    dey
    bne loop                ; Y is 0 after this
    lda $70
    cmp #$7b
    bne different           ; A is $7b after this
    ldx $71
    cpx #3
    bne different           ; X is 3 after this
    lda $72
    bne different           ; A is 0 after this
    lda $73
    beq different           ; (nothing more known: A isn't 0)
    ldy $74
    bne next                ; (a branch to the next instruction says nothing)
next
    tax
    bit $75
    bne different           ; (BIT's Z is from memory: nothing more known)
    lda $76
    sta $77                 ; (STA doesn't change Z)
    bne different           ; A is 0 after this
    rts
different
    rts
