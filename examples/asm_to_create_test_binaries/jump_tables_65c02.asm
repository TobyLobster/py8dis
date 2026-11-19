; The 65C02's 'jmp (table,x)', for jump_tables_65c02 (see its control file):
; X is 0, 2, 4 or 6 after 'and #3 : asl', so py8dis finds the table of four
; words and traces the code they point to. Assemble with:
;
;   acme -o ../orig/jump_tables_65c02.orig jump_tables_65c02.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 65c02

    * = $2000

start
    lda $70
    and #3
    asl
    tax
    jmp (table,x)

table
    !word routine_a, routine_b, routine_c, routine_d

routine_a
    lda #$0a
    rts
routine_b
    lda #$0b
    rts
routine_c
    lda #$0c
    rts
routine_d
    lda #$0d
    rts
