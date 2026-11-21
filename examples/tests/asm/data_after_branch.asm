; Data after a branch that's always taken (November 2026), for
; data_after_branch (see its control file): tracing runs on past a
; conditional branch into the bytes after it, but once py8dis knows the
; branch is always taken, and the code reads those bytes as a table, and as
; code they run straight into an opcode that doesn't exist, they're data.
; And where the control file marks such bytes as data, the instructions
; tracing found there aren't shown in '; overlapping' comments. Assemble
; with:
;
;   acme -o ../orig/data_after_branch.orig data_after_branch.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr clearly_data
    jsr ends_in_rts
    jsr reached_elsewhere
    jsr marked_data
    jsr marked_data_with_jsr
    rts

; 1. The BEQ is always taken (X is 0), and table1 is read with Y 0 to 3. As
;    code, its bytes are 'lda ($00,x)' then $22, which isn't an opcode: so
;    it's a table of 4 bytes
clearly_data
    ldy $70
    cpy #4
    bcs +
    lda table1,y
    sta $71
+   ldx #0
    beq +
table1
    !byte $a1, $00, $22, $11
+   rts

; 2. The same, but as code the bytes are 'lda #0 : rts', which could be
;    code: they're left as code
ends_in_rts
    ldy $70
    cpy #4
    bcs +
    lda table2,y
    sta $71
+   ldx #0
    beq +
table2
    !byte $a9, $00, $60, $ea
+   rts

; 3. The same, as 'nop' then $02 (not an opcode), but a branch elsewhere goes
;    to the NOP: it's left as code
reached_elsewhere
    lda $72
    bne table3
    ldy $70
    cpy #4
    bcs +
    lda table3,y
    sta $71
+   ldx #0
    beq +
table3
    !byte $ea, $02, $33, $44
+   rts

; 4. The BEQ is always taken, and the control file marks the bytes after it
;    as data. As code, they're 'sty $86 : sty $e298' then $02: tracing ran
;    on into them, but they get no '; overlapping' comments (and no labels
;    for $86 and $e298)
marked_data
    ldx #0
    beq +
table4
    !byte $84, $86, $8c, $98, $e2, $02
+   rts

; 5. The same, but as code the bytes are 'sty $86 : jsr $3000': the JSR's
;    target was traced, so both keep their comments
marked_data_with_jsr
    ldx #0
    beq +
table5
    !byte $84, $86, $20, $00, $30, $02
+   rts
