; Jump tables that py8dis finds itself (November 2026), for jump_tables (see
; its control file): the code jumps through a table with an index whose
; possible values are known, so py8dis marks the table's entries as code
; addresses and traces the code they point to. Assemble with:
;
;   acme -o ../orig/jump_tables.orig jump_tables.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr rts_trick
    jsr jmp_indirect
    jsr self_modified
    jsr lower_bound
    jsr no_guard
    jsr marked_by_control_file
    rts

; 1. The RTS trick, with the addresses minus 1 as words: A is less than 3
;    after the BCS, so X is 0, 2 or 4
rts_trick
    lda $70
    cmp #3
    bcs done
    asl
    tax
    lda table1+1,x
    pha
    lda table1,x
    pha
    rts

; 2. Jumping through an address stored in zero page, from tables of the low
;    and high bytes: Y is 0 to 3 after AND #3
jmp_indirect
    lda $71
    and #3
    tay
    lda table2_low,y
    sta $80
    lda table2_high,y
    sta $81
    jmp ($80)

; 3. Storing the address in the operand of a JSR that follows: X is 0 or 1
self_modified
    ldx $72
    cpx #2
    bcs done
    lda table3_low,x
    sta call+1
    lda table3_high,x
    sta call+2
call
    jsr $0000
done
    rts

; 4. An index that's at least 2 (after the BCC) and less than 4 (after the
;    BCS), so the table's entries are the two at table4+4 and table4+6
lower_bound
    lda $73
    cmp #2
    bcc done
    cmp #4
    bcs done
    asl
    tax
    lda table4+1,x
    pha
    lda table4,x
    pha
    rts

; 5. No guard: nothing is known about the index, so the table isn't found
no_guard
    lda $74
    asl
    tax
    lda table5+1,x
    pha
    lda table5,x
    pha
    rts

; 6. The control file marks this table itself, so py8dis leaves it alone
marked_by_control_file
    lda $75
    and #1
    asl
    tax
    lda table6+1,x
    pha
    lda table6,x
    pha
    rts

table1
    !word routine1a - 1, routine1b - 1, routine1c - 1
table2_low
    !byte <routine2a, <routine2b, <routine2c, <routine2a
table2_high
    !byte >routine2a, >routine2b, >routine2c, >routine2a
table3_low
    !byte <routine3a, <routine3b
table3_high
    !byte >routine3a, >routine3b
table4
    !word 0, 0, routine4a - 1, routine4b - 1
table5
    !word routine5a - 1, routine5b - 1
table6
    !word routine6a - 1, routine6b - 1

routine1a
    lda #$1a
    rts
routine1b
    lda #$1b
    rts
routine1c
    lda #$1c
    rts
routine2a
    lda #$2a
    rts
routine2b
    lda #$2b
    rts
routine2c
    lda #$2c
    rts
routine3a
    lda #$3a
    rts
routine3b
    lda #$3b
    rts
routine4a
    lda #$4a
    rts
routine4b
    lda #$4b
    rts
routine5a
    lda #$5a
    rts
routine5b
    lda #$5b
    rts
routine6a
    lda #$6a
    rts
routine6b
    lda #$6b
    rts
