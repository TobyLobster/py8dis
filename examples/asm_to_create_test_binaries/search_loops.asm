; A 65C02 program for python/search_loops.py: loops that search a table for
; a byte, loops that compare two tables, and loops that clear memory with
; the 65C02's STZ, commented by the built in snippets (see
; py8dis/snippets6502.py). Assemble with:
;
;   acme -o ../orig/search_loops.orig search_loops.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 65c02

ptr = $80
ptr2 = $82

* = $2000

start
    ; 1. CMP table,X counting up to a limit: the 16 bytes from key_table
    lda $70
    ldx #0
loop1
    cmp key_table,x
    beq found1
    inx
    cpx #16
    bne loop1
found1

    ; 2. CMP table,X counting down past zero from 5: the 6 bytes from table2
    lda $71
    ldx #5
loop2
    cmp table2,x
    beq found2
    dex
    bpl loop2
found2

    ; 3. LDA table,X and BEQ: the first zero byte in the 256 bytes from
    ; string3
    ldx #0
loop3
    lda string3,x
    beq found3
    inx
    bne loop3
found3

    ; 4. LDA table,Y, CMP #value and BNE: the first byte other than a space
    ; in the 40 bytes from buffer4
    ldy #0
loop4
    lda buffer4,y
    cmp #' '
    bne found4
    iny
    cpy #40
    bcc loop4
found4

    ; 5. LDA (ptr),Y and CMP #value, with the pointer set just before: the
    ; first carriage return in the 256 bytes from text5
    lda #<text5
    sta ptr
    lda #>text5
    sta ptr+1
    ldy #0
loop5
    lda (ptr),y
    cmp #$0d
    beq found5
    iny
    bne loop5
found5

    ; 6. X isn't known on the way in, counting up to a limit: from table6+X
    ; to table6+7
    lda $72
    ldx $73
loop6
    cmp table6,x
    beq found6
    inx
    cpx #8
    bne loop6
found6

    ; 7. X isn't known on the way in, counting down to zero: the X bytes from
    ; table7+1 (X isn't compared once it's zero)
    ldx $74
loop7
    lda table7,x
    beq found7
    dex
    bne loop7
found7

    ; 8. STZ table-1,X counting down to zero from 16: the 16 bytes from table8
    ldx #16
loop8
    stz table8-1,x
    dex
    bne loop8

    ; 9. Two STZs counting up to a limit: the 8 bytes from $90 and the 8 from
    ; table9
    ldx #0
loop9
    stz $90,x
    stz table9,x
    inx
    cpx #8
    bne loop9

    ; 10. STZ with X not known, counting down past zero: X+1 bytes from $a0
    ldx $75
loop10
    stz $a0,x
    dex
    bpl loop10

    ; 11. The table's address is stored into the CMP before the loop (so
    ; that the operand assembled, $ffff, isn't the table): X+1 bytes from the
    ; address stored there
    lda $76
    sta loop11+1
    lda $77
    sta loop11+2
    lda $78
    ldx $79
loop11
    cmp $ffff,x
    beq found11
    dex
    bpl loop11
found11

    ; 12. Not a search: the loop's first instruction is also branched to
    ; from outside the loop, so it gets no comment
    lda $7a
    ldx #0
    bit $7b
    bmi loop12
    ldx #2
loop12
    cmp table2,x
    beq found12
    inx
    cpx #6
    bne loop12
found12

    ; 13. Comparing two tables with CMP, counting up to a limit: the 4 bytes
    ; from table6 with those from key_table
    ldx #0
loop13
    lda table6,x
    cmp key_table,x
    bne found13
    inx
    cpx #4
    bne loop13
found13

    ; 14. Comparing with EOR, in zero page, counting down to zero: the 4
    ; bytes from $90 with those from $94
    ldx #4
loop14
    lda $8f,x
    eor $93,x
    bne found14
    dex
    bne loop14
found14

    ; 15. Comparing through a pointer, indexed by Y from 0 and counted by X,
    ; which isn't known: X bytes from (ptr2) with buffer4
    lda $7c
    sta ptr2
    lda $7d
    sta ptr2+1
    ldy #0
    ldx $7e
loop15
    lda (ptr2),y
    cmp buffer4,y
    bne found15
    iny
    dex
    bne loop15
found15

    ; 16. Searching, indexed by Y from 2 and counted by X from 3 past zero:
    ; the 4 bytes from table2+2
    lda $7f
    ldx #3
    ldy #2
loop16
    cmp table2,y
    beq found16
    iny
    dex
    bpl loop16
found16

    ; 17. Searching for 0, indexed by Y down from 5 and counted by X from 2
    ; past zero: the 3 bytes from table6+3
    ldx #2
    ldy #5
loop17
    lda table6,y
    beq found17
    dey
    dex
    bpl loop17
found17
    rts

key_table
    !byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
table2
    !byte $20, $21, $22, $23, $24, $25
table6
    !byte $30, $31, $32, $33, $34, $35, $36, $37
table7
    !byte 0, $41, $42, $43, $44

* = $2200
string3
    !fill 256, $55
buffer4
    !fill 40, ' '
text5
    !fill 256, $66
table8
    !fill 16, $77
table9
    !fill 8, $88
