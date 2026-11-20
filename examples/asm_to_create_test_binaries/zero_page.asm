; What py8dis knows about zero page (November 2026), for zero_page (see its
; control file): a byte stored in zero page is known when it's loaded again
; (or used by AND, CMP, INC and the like), across calls to subroutines that
; don't write it, so the comments that come from what's known about the
; registers come from there too. Assemble with:
;
;   acme -o ../orig/zero_page.orig zero_page.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr stored_then_loaded
    jsr changed_in_place
    jsr indexed_store
    jsr table_through_variable
    jsr table_through_pointer
    jsr clear_buffer
    jsr polling_loop
    jsr across_calls
    jsr not_tracked
    rts

; 1. A byte stored and loaded again: bit 7 of $71 is set, so LDX $71 sets N
;    and BMI is always taken
stored_then_loaded
    lda $70
    ora #$80
    sta $71
    lda #0
    sta $72
    ldx $71
    bmi +
    nop
+   rts

; 2. INC, DEC and ASL of a known byte: $73 goes from $ff to 0 (so BEQ is
;    always taken), and $74 from $40 to $80 (so BMI is)
changed_in_place
    ldy #$ff
    sty $73
    inc $73
    beq +
    nop
+   lda #$41
    sta $74
    dec $74
    asl $74
    bmi +
    nop
+   rts

; 3. A store indexed by a known X writes $92, and a load from $92 gets the
;    value back; a store indexed by an unknown X could write anywhere in
;    zero page, so nothing is known about $92 afterwards
indexed_store
    ldx #2
    lda #5
    sta $90,x
    lda #0
    lda $92
    cmp #5
    beq +
    nop
+   ldx $70
    lda #0
    sta $90,x
    lda $92
    cmp #5
    beq +
    nop
+   rts

; 4. A mask kept in zero page: after 'and $75', X is 0 to 15, so the table
;    is 16 bytes
table_through_variable
    lda #$0f
    sta $75
    lda #0
    sta $80
    lda $70
    and $75
    tax
    lda table4,x
    sta $81
    rts

table4
    !text "ON[", 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
after_table4
    !byte $ff

; 5. A table read through a pointer in zero page: '(ptr),y' with Y 0 to 3,
;    and the pointer set to table5 before (so the loads are written as the
;    table's label's low and high bytes)
table_through_pointer
    lda #<table5
    sta $76
    lda #>table5
    sta $77
    lda $70
    and #3
    tay
    lda ($76),y
    rts

table5
    !byte $10, $20, $40, $80
after_table5
    !text "XYZ"

; 6. A loop clearing a buffer through a pointer set before it: the comment
;    names the buffer, not the pointer (and the loads are written as the
;    buffer's low and high bytes)
clear_buffer
    lda #<buffer
    sta $78
    lda #>buffer
    sta $79
    lda #0
    tay
-   sta ($78),y
    iny
    bne -
    rts

; 7. A loop waiting for an interrupt to clear bit 7 of $7a: the loop doesn't
;    write $7a, so py8dis doesn't take it to stay $e0 (or say the branch is
;    always taken)
polling_loop
    lda #$e0
    sta $7a
-   lda $7a
    bmi -
    rts

; 8. A call to a subroutine that doesn't write $7b leaves it known (so BEQ
;    is always taken); a call to one that does write it doesn't
across_calls
    lda #3
    sta $7b
    jsr reads_only
    lda $7b
    cmp #3
    beq +
    nop
+   jsr writes_7b
    lda $7b
    cmp #3
    beq +
    nop
+   rts

reads_only
    lda $70
    rts

writes_7b
    lda $70
    sta $7b
    rts

; 9. $7e is I/O (io_range() in the control file), so what's stored there
;    isn't what's read back
not_tracked
    lda #$80
    sta $7e
    lda $7e
    bmi +
    nop
+   rts

buffer = $0400
