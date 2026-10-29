; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070
l0071   = &0071

; Other
l0300   = &0300
l0301   = &0301
l0302   = &0302
l0303   = &0303

    org &2000

.pydis_start
.start
    lda #<handler_2074                                                ; 2000: a9 74       .t
    ldx #>handler_2074                                                ; 2002: a2 20       .
    sei                                                               ; 2004: 78          x
    ; Set the vector at $0300 to handler_2074
    stx l0301                                                         ; 2005: 8e 01 03    ...
    sta l0300                                                         ; 2008: 8d 00 03    ...
    cli                                                               ; 200b: 58          X
    lda #<handler_2075                                                ; 200c: a9 75       .u
    ; Set the vector at $0302 to handler_2075
    sta l0302                                                         ; 200e: 8d 02 03    ...
    lda #>handler_2075                                                ; 2011: a9 20       .
    sta l0303                                                         ; 2013: 8d 03 03    ...
    lda #<handler_2076                                                ; 2016: a9 76       .v
    ; Set the vector at $0302 to handler_2076
    sta l0302                                                         ; 2018: 8d 02 03    ...
    lda #>handler_2076                                                ; 201b: a9 20       .
    sta l0303                                                         ; 201d: 8d 03 03    ...
    lda #&12                                                          ; 2020: a9 12       ..
    ; Set the low byte of the vector at $0300 to $12
    sta l0300                                                         ; 2022: 8d 00 03    ...
    jsr subroutine                                                    ; 2025: 20 72 20     r
    lda #&34 ; '4'                                                    ; 2028: a9 34       .4
    ; Set the low byte of the vector at $0302 to $34 (the high byte isn't known)
    sta l0302                                                         ; 202a: 8d 02 03    ...
    lda l0070                                                         ; 202d: a5 70       .p
    sta l0303                                                         ; 202f: 8d 03 03    ...
    ldx #<handler_2077                                                ; 2032: a2 77       .w
    txa                                                               ; 2034: 8a          .  ; A=&77
    ; Set the vector at $0300 to handler_2077
    sta l0300                                                         ; 2035: 8d 00 03    ...
    lda #>handler_2077                                                ; 2038: a9 20       .
    sta l0301                                                         ; 203a: 8d 01 03    ...
    lda #3                                                            ; 203d: a9 03       ..
    sta l0070                                                         ; 203f: 85 70       .p
    ldx #5                                                            ; 2041: a2 05       ..
    jsr print                                                         ; 2043: 20 73 20     s ; Print with 3 at &70, X=5
    lda #3                                                            ; 2046: a9 03       ..
    sta l0070                                                         ; 2048: 85 70       .p
    ldx #6                                                            ; 204a: a2 06       ..
    jsr print                                                         ; 204c: 20 73 20     s
    lda l0071                                                         ; 204f: a5 71       .q
    sta l0070                                                         ; 2051: 85 70       .p
    ldx #5                                                            ; 2053: a2 05       ..
    jsr print                                                         ; 2055: 20 73 20     s
    lda #7                                                            ; 2058: a9 07       ..
    sta l0070                                                         ; 205a: 85 70       .p
    lda l0071                                                         ; 205c: a5 71       .q
    sta l0071                                                         ; 205e: 85 71       .q
    ldx #5                                                            ; 2060: a2 05       ..
    jsr print                                                         ; 2062: 20 73 20     s ; Print with 7 at &70, X=5, and something at &71
    lda #&78 ; 'x'                                                    ; 2065: a9 78       .x
    ; Set the low byte of the vector at $0302 to $78
    sta l0302                                                         ; 2067: 8d 02 03    ...
    bne c206c                                                         ; 206a: d0 00       .. ; ALWAYS branch

; &206c referenced 1 time by &206a
.c206c
    lda #&20 ; ' '                                                    ; 206c: a9 20       .
    ; Set the high byte of the vector at $0302 to $20
    sta l0303                                                         ; 206e: 8d 03 03    ...
    rts                                                               ; 2071: 60          `

; &2072 referenced 1 time by &2025
.subroutine
    rts                                                               ; 2072: 60          `

; &2073 referenced 4 times by &2043, &204c, &2055, &2062
.print
    rts                                                               ; 2073: 60          `

.handler_2074
    rti                                                               ; 2074: 40          @

.handler_2075
    rti                                                               ; 2075: 40          @

.handler_2076
    rti                                                               ; 2076: 40          @

.handler_2077
    rti                                                               ; 2077: 40          @

    equb &40                                                          ; 2078: 40          @
.pydis_end

    assert &74 == <handler_2074
    assert &75 == <handler_2075
    assert &76 == <handler_2076
    assert &77 == <handler_2077
    assert &20 == >handler_2074
    assert &20 == >handler_2075
    assert &20 == >handler_2076
    assert &20 == >handler_2077

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l0070:        5
;     l0302:        4
;     l0303:        4
;     print:        4
;     l0071:        3
;     l0300:        3
;     l0301:        2
;     c206c:        1
;     subroutine:   1

; Automatically generated labels:
;     c206c
;     l0070
;     l0071
;     l0300
;     l0301
;     l0302
;     l0303

; Stats:
;
;     Total size (Code + Data) = 121 bytes
;     Code                     = 120 bytes (99%)
;     Data                     = 1 bytes (1%)
;
;     Number of instructions   = 56
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

