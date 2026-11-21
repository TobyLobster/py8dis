; Tables of data that py8dis finds itself (November 2026), for data_tables
; (see its control file): the code reads them with an index whose possible
; values are known, so py8dis says how big each one is and how it's used,
; and marks tables of pointers as the labels they point to. Assemble with:
;
;   acme -o ../orig/data_tables.orig data_tables.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr byte_table
    jsr count_down
    jsr text_table
    jsr overlapping
    jsr word_table
    jsr pointer_table_split
    jsr pointer_table_words
    jsr marked_by_control_file
    jsr unknown_index
    rts

; 1. A table of 8 bytes, read with X after 'cmp #8 : bcs': some of its bytes
;    look like text ("ON["), which the search for strings would otherwise
;    find, so py8dis marks it as bytes
byte_table
    lda $70
    cmp #8
    bcs +
    tax
    lda table1,x
    sta $80
+   rts

; 2. A loop counting down from 11 to 0 (after DEX, X is $ff or 0 to 10):
;    a table of 12 bytes (the copy at $0400 isn't loaded, so isn't a table)
count_down
    ldx #11
-   lda table2,x
    sta $0400,x
    dex
    bpl -
    rts

; 3. A table of text (hex digits), read with X after 'and #$0f': it gets a
;    comment, but is left as a string
text_table
    lda $71
    and #$0f
    tax
    lda hex_digits,x
    rts

; 4. Two tables that overlap by a byte: each has a comment of its own
overlapping
    lda $72
    and #3
    tax
    lda table4a,x
    ldy table4b,x
    rts

; 5. A table of words, read as low and high bytes with X going up in twos
word_table
    lda $73
    and #3
    asl
    tax
    lda table5,x
    ldy table5+1,x
    rts

; 6. A table of pointers (their low and high bytes in tables of their own),
;    copied into zero page and used: each is written as its label
pointer_table_split
    lda $74
    and #3
    tax
    lda messages_low,x
    sta $90
    lda messages_high,x
    sta $91
    ldy #0
    lda ($90),y
    rts

; 7. A table of pointers as words
pointer_table_words
    lda $75
    and #1
    asl
    tax
    lda pointers,x
    sta $92
    lda pointers+1,x
    sta $93
    ldy #0
    lda ($92),y
    rts

; 8. The control file marks this table itself, so py8dis leaves it alone
marked_by_control_file
    lda $76
    and #3
    tax
    lda table8,x
    rts

; 9. Nothing is known about the index, so this table isn't marked
unknown_index
    ldx $77
    lda table9,x
    rts

table1
    !byte $10, $4f, $4e, $5b, $00, $ff, $80, $01
table2
    !byte 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
hex_digits
    !text "0123456789ABCDEF"
table4a
    !byte $11, $22, $33
table4b
    !byte $44, $55, $66, $77
table5
    !word $1234, $5678, $9abc, $def0
messages_low
    !byte <message0, <message1, <message2, <message3
messages_high
    !byte >message0, >message1, >message2, >message3
pointers
    !word message0, message2
table8
    !byte $de, $ad, $be, $ef
table9
    !byte $81, $82, $83, $84

message0
    !text "ZERO", 0
message1
    !text "ONE", 0
message2
    !text "TWO", 0
message3
    !text "THREE", 0

; 10. A table of 8 bytes with text in it ("BRIDGE"): the text is a string,
;     the rest of the table bytes, and the bytes after it start a line of
;     their own (the control file gives this as an entry point)
text_with_bytes
    ldx #7
-   lda packet,x
    sta $0400,x
    dex
    bpl -
    rts

; 11. X is 0 to 127 after BMI, but that's only because nothing was known
;     about it before, so it isn't taken to size a table
half_known
    ldx $78
    bmi +
    lda table11,x
+   rts

; 12. A table of words inside a table of bytes (the 6 bytes a loop copies,
;     the last 4 of which are 2 words): the words stay words
words_in_bytes
    ldy #5
-   lda block,y
    sta $0500,y
    dey
    bpl -
    lda $79
    and #1
    asl
    tax
    lda block_words,x
    ldy block_words+1,x
    rts

packet
    !byte $82
    !text "BRIDGE"
    !byte $9c
after_packet
    !byte $ff, $fe, $fd
table11
    !byte $91, $92, $93, $94
block
    !byte $a1, $a2
block_words
    !word $1234, $5678
