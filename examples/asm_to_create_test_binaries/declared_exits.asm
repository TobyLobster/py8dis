; What subroutines that py8dis can't follow leave behind, as their
; subroutine() declares it (November 2026), for declared_exits (see its
; control file): the OS calls whose on_exit acorn.bbc() gives (OSWRCH
; preserves A, X and Y and clears D, OSRDCH preserves X and Y), a routine
; outside the binary, and one in it that jumps through a vector. Assemble
; with:
;
;   acme -o ../orig/declared_exits.orig declared_exits.asm
;
; (It isn't meant to do anything useful when run.)

oswrch = $ffee
osrdch = $ffe0

    * = $2000

start
    ; 1. A loop that prints a message with OSWRCH, which preserves Y: so Y
    ;    is 0 to 4 in the loop (the message is a table of 5 bytes) and 5
    ;    after it
    ldy #0
-   lda message,y
    jsr oswrch
    iny
    cpy #5
    bne -
    sty $70                 ; Y=5

    ; 2. OSWRCH preserves A, so the second call writes 'A' again; and it
    ;    clears D, so the ADC is worked out (A=3)
    lda #'A'
    jsr oswrch
    jsr oswrch
    lda #1
    clc
    adc #2
    sta $71                 ; A=3

    ; 3. OSRDCH preserves X (but not A)
    ldx #3
    jsr osrdch
    stx $72                 ; X=3

    ; 4. A routine outside the binary, which the control file declares
    ;    preserves X and clears C
    ldx #7
    jsr $3000
    stx $73                 ; X=7
    bcc +                   ; ALWAYS branch
+
    ; 5. A routine in the binary that jumps through a vector, which the
    ;    control file declares preserves Y
    ldy #9
    jsr vectored
    sty $74                 ; Y=9
    rts

vectored
    jmp ($0230)

message
    !text "HELLO"
