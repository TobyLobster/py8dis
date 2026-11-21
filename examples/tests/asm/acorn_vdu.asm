; Code that writes VDU sequences with OSWRCH, for python/acorn_vdu.py, which
; decodes them (acorn.py). Assemble with:
;
;   acme -o ../orig/acorn_vdu.orig acorn_vdu.asm

oswrch = $ffee
osasci = $ffe3
osnewl = $ffe7
column = $70

    * = $2000

start
    ; MODE 7
    lda #22
    jsr oswrch
    lda #7
    jsr oswrch

    ; Turn the cursor off: VDU 23,1,0;0;0;0; (A is preserved by OSWRCH)
    lda #23
    jsr oswrch
    lda #1
    jsr oswrch
    lda #0
    jsr oswrch
    jsr oswrch
    jsr oswrch
    jsr oswrch
    jsr oswrch
    jsr oswrch
    jsr oswrch
    jsr oswrch

    ; Logical colour 1 to physical colour 4
    ldx #19
    txa
    jsr oswrch
    lda #1
    jsr oswrch
    lda #4
    jsr oswrch
    lda #0
    jsr oswrch
    jsr oswrch
    jsr oswrch

    ; TAB(X,Y), with the coordinates in X and Y
    lda #31
    jsr oswrch
    txa
    jsr oswrch
    tya
    jsr oswrch

    ; TAB(column,3): the column isn't known
    lda #31
    jsr oswrch
    lda column
    jsr oswrch
    lda #3
    jsr oswrch

    ; PLOT 69,640,512
    lda #25
    jsr oswrch
    lda #69
    jsr oswrch
    lda #<640
    jsr oswrch
    lda #>640
    jsr oswrch
    lda #<512
    jsr oswrch
    lda #>512
    jsr oswrch

    ; Text, then a new line (CR, LF)
    lda #'H'
    jsr oswrch
    lda #'i'
    jsr oswrch
    lda #13
    jsr oswrch
    lda #10
    jsr oswrch

    ; OSASCI's CR is a new line; OSNEWL's comment is its own
    lda #13
    jsr osasci
    jsr osnewl
    rts

; The end of a sequence that the caller started (the last three bytes of a
; PLOT's coordinates), then TAB(5,6): taken that way rather than as three
; VDU 0s, which do nothing
end_of_plot
    lda #0
    jsr oswrch
    jsr oswrch
    jsr oswrch
    lda #31
    jsr oswrch
    lda #5
    jsr oswrch
    lda #6
    jmp oswrch
