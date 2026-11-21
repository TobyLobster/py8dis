; Redundant instructions (October 2026), for redundant_test (see its control
; file): py8dis comments an instruction whose results (registers and flags)
; are all changed again before anything uses them, '; Redundant
; instruction?'.
; Assemble with: acme -o ../orig/redundant_test.orig redundant_test.asm

io = $fe40                  ; (I/O, see the control file)

    * = $2000

start
    lda #3
    !byte $2c               ; (BIT abs: not redundant, since it's there to
                            ; skip over the LDA #4 for code that comes here)
middle
    lda #4
    ldx #5                  ; redundant: TAX overwrites X, N and Z
    tax
    clc                     ; not redundant: ADC uses the carry
    adc #1
    sta $78
    lda $70                 ; redundant: PLA overwrites A, N and Z
    pla
    lda $71                 ; redundant: so is the AND that uses it,
    and #3                  ; since LDA $72 overwrites A, N and Z
    lda $72
    sec                     ; redundant: SEC again
    sec                     ; redundant: CPX sets the carry
    cpx $73                 ; redundant: the same compare again
    cpx $73
    bne skip                ; (the flags are used here)
    lda $74                 ; not redundant: STA uses A
    sta $75
    lda $76                 ; redundant: LDA ($77),Y overwrites A, N and Z
    ldx io                  ; not redundant: reading I/O can have side effects
    ldx #0
    lda ($77),y             ; not redundant: it could be reading I/O
    lda #1
    ldy #1                  ; not redundant: the subroutine could use Y
    jsr skip
    ldy #2
    beq middle
skip
    rts
