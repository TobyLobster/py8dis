; Assemble with Baron, which writes the program to the file named in its
; section (jump_tables_baron), in the folder given with -p:
;     baron -p . jump_tables_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0000   = &0000
l0070   = &0070
l0071   = &0071
l0072   = &0072
l0073   = &0073
l0074   = &0074
l0075   = &0075
l0080   = &0080
l0081   = &0081

section pydis, org = &2000, filename = "jump_tables_baron"

.pydis_start
.start
    jsr sub_c2013                                                     ; 2000: 20 13 20     .
    jsr sub_c2024                                                     ; 2003: 20 24 20     $
    jsr sub_c2036                                                     ; 2006: 20 36 20     6
    jsr sub_c204c                                                     ; 2009: 20 4c 20     L
    jsr sub_c2061                                                     ; 200c: 20 61 20     a
    jsr sub_c206e                                                     ; 200f: 20 6e 20     n
    rts                                                               ; 2012: 60          `

; &2013 referenced 1 time by &2000
.sub_c2013
    lda l0070                                                         ; 2013: a5 70       .p
    cmp #3                                                            ; 2015: c9 03       ..
    bcs return_1                                                      ; 2017: b0 32       .2
    asl a                                                             ; 2019: 0a          .
    tax                                                               ; 201a: aa          .
    lda l207e,x                                                       ; 201b: bd 7e 20    .~
    pha                                                               ; 201e: 48          H
    lda l207d,x                                                       ; 201f: bd 7d 20    .}
    pha                                                               ; 2022: 48          H
    rts                                                               ; 2023: 60          `

; &2024 referenced 1 time by &2003
.sub_c2024
    lda l0071                                                         ; 2024: a5 71       .q
    and #3                                                            ; 2026: 29 03       ).
    tay                                                               ; 2028: a8          .
    lda l2083,y                                                       ; 2029: b9 83 20    ..
    sta l0080                                                         ; 202c: 85 80       ..
    lda l2087,y                                                       ; 202e: b9 87 20    ..
    sta l0081                                                         ; 2031: 85 81       ..
    jmp (l0080)                                                       ; 2033: 6c 80 00    l..

; &2036 referenced 1 time by &2006
.sub_c2036
    ldx l0072                                                         ; 2036: a6 72       .r
    cpx #2                                                            ; 2038: e0 02       ..
    bcs return_1                                                      ; 203a: b0 0f       ..
    lda l208b,x                                                       ; 203c: bd 8b 20    ..
    sta l2049                                                         ; 203f: 8d 49 20    .I
    lda l208d,x                                                       ; 2042: bd 8d 20    ..
    sta l204a                                                         ; 2045: 8d 4a 20    .J
.c2048
l2049 = c2048+1
l204a = c2048+2
    jsr l0000                                                         ; 2048: 20 00 00     ..
; &2049 referenced 1 time by &203f
; &204a referenced 1 time by &2045
; &204b referenced 4 times by &2017, &203a, &2050, &2054
.return_1
    rts                                                               ; 204b: 60          `

; &204c referenced 1 time by &2009
.sub_c204c
    lda l0073                                                         ; 204c: a5 73       .s
    cmp #2                                                            ; 204e: c9 02       ..
    bcc return_1                                                      ; 2050: 90 f9       ..
    cmp #4                                                            ; 2052: c9 04       ..
    bcs return_1                                                      ; 2054: b0 f5       ..
    asl a                                                             ; 2056: 0a          .
    tax                                                               ; 2057: aa          .
    lda l2090,x                                                       ; 2058: bd 90 20    ..
    pha                                                               ; 205b: 48          H
    lda l208f,x                                                       ; 205c: bd 8f 20    ..
    pha                                                               ; 205f: 48          H
    rts                                                               ; 2060: 60          `

; &2061 referenced 1 time by &200c
.sub_c2061
    lda l0074                                                         ; 2061: a5 74       .t
    asl a                                                             ; 2063: 0a          .
    tax                                                               ; 2064: aa          .
    lda l2098,x                                                       ; 2065: bd 98 20    ..
    pha                                                               ; 2068: 48          H
    lda l2097,x                                                       ; 2069: bd 97 20    ..
    pha                                                               ; 206c: 48          H
    rts                                                               ; 206d: 60          `

; &206e referenced 1 time by &200f
.sub_c206e
    lda l0075                                                         ; 206e: a5 75       .u
    and #1                                                            ; 2070: 29 01       ).
    asl a                                                             ; 2072: 0a          .
    tax                                                               ; 2073: aa          .
    lda l209c,x                                                       ; 2074: bd 9c 20    ..
    pha                                                               ; 2077: 48          H
    lda table6,x                                                      ; 2078: bd 9b 20    ..
    pha                                                               ; 207b: 48          H
    rts                                                               ; 207c: 60          `

; A jump table of 3 entries (each the address minus 1, for the RTS at &2023)
; &207d referenced 1 time by &201f
.l207d
l207e = l207d+1
    equw sub_c209f - 1                                                ; 207d: 9e 20       .
; &207e referenced 1 time by &201b
    equw sub_c20a2 - 1                                                ; 207f: a1 20       .
    equw sub_c20a5 - 1                                                ; 2081: a4 20       .
; The low bytes of a jump table of 4 entries (for the JMP at &2033)
; &2083 referenced 1 time by &2029
.l2083
    equb <sub_c20a8                                                   ; 2083: a8          .
    equb <sub_c20ab                                                   ; 2084: ab          .
    equb <sub_c20ae                                                   ; 2085: ae          .
    equb <sub_c20a8                                                   ; 2086: a8          .
; The high bytes of the jump table
; &2087 referenced 1 time by &202e
.l2087
    equb >sub_c20a8                                                   ; 2087: 20
    equb >sub_c20ab                                                   ; 2088: 20
    equb >sub_c20ae                                                   ; 2089: 20
    equb >sub_c20a8                                                   ; 208a: 20
; The low bytes of a jump table of 2 entries (for the JSR at &2048)
; &208b referenced 1 time by &203c
.l208b
    equb <sub_c20b1                                                   ; 208b: b1          .
    equb <sub_c20b4                                                   ; 208c: b4          .
; The high bytes of the jump table
; &208d referenced 1 time by &2042
.l208d
    equb >sub_c20b1                                                   ; 208d: 20
    equb >sub_c20b4                                                   ; 208e: 20
; &208f referenced 1 time by &205c
.l208f
    equb 0                                                            ; 208f: 00          .
; &2090 referenced 1 time by &2058
.l2090
    equb 0, 0, 0                                                      ; 2090: 00 00 00    ...
; A jump table of 2 entries (each the address minus 1, for the RTS at &2060)
    equw sub_c20b7 - 1                                                ; 2093: b6 20       .
    equw sub_c20ba - 1                                                ; 2095: b9 20       .
; &2097 referenced 1 time by &2069
.l2097
    equb &bc                                                          ; 2097: bc          .
; &2098 referenced 1 time by &2065
.l2098
    equb &20, &bf, &20                                                ; 2098: 20 bf 20     .
; &209b referenced 1 time by &2078
.table6
l209c = table6+1
    equw sub_c20c3 - 1                                                ; 209b: c2 20       .
; &209c referenced 1 time by &2074
    equw sub_c20c6 - 1                                                ; 209d: c5 20       .

.sub_c209f
    lda #&1a                                                          ; 209f: a9 1a       ..
    rts                                                               ; 20a1: 60          `

.sub_c20a2
    lda #&1b                                                          ; 20a2: a9 1b       ..
    rts                                                               ; 20a4: 60          `

.sub_c20a5
    lda #&1c                                                          ; 20a5: a9 1c       ..
    rts                                                               ; 20a7: 60          `

.sub_c20a8
    lda #&2a ; '*'                                                    ; 20a8: a9 2a       .*
    rts                                                               ; 20aa: 60          `

.sub_c20ab
    lda #&2b ; '+'                                                    ; 20ab: a9 2b       .+
    rts                                                               ; 20ad: 60          `

.sub_c20ae
    lda #&2c ; ','                                                    ; 20ae: a9 2c       .,
    rts                                                               ; 20b0: 60          `

.sub_c20b1
    lda #&3a ; ':'                                                    ; 20b1: a9 3a       .:
    rts                                                               ; 20b3: 60          `

.sub_c20b4
    lda #&3b ; ';'                                                    ; 20b4: a9 3b       .;
    rts                                                               ; 20b6: 60          `

.sub_c20b7
    lda #&4a ; 'J'                                                    ; 20b7: a9 4a       .J
    rts                                                               ; 20b9: 60          `

.sub_c20ba
    lda #&4b ; 'K'                                                    ; 20ba: a9 4b       .K
    rts                                                               ; 20bc: 60          `

    equb &a9, &5a, &60, &a9, &5b, &60                                 ; 20bd: a9 5a 60... .Z`

.sub_c20c3
    lda #&6a ; 'j'                                                    ; 20c3: a9 6a       .j
    rts                                                               ; 20c5: 60          `

.sub_c20c6
    lda #&6b ; 'k'                                                    ; 20c6: a9 6b       .k
    rts                                                               ; 20c8: 60          `

.pydis_end

    assert (<sub_c20a8) = &a8
    assert (<sub_c20ab) = &ab
    assert (<sub_c20ae) = &ae
    assert (<sub_c20b1) = &b1
    assert (<sub_c20b4) = &b4
    assert (>sub_c20a8) = &20
    assert (>sub_c20ab) = &20
    assert (>sub_c20ae) = &20
    assert (>sub_c20b1) = &20
    assert (>sub_c20b4) = &20
    assert (sub_c209f - 1) = &209e
    assert (sub_c20a2 - 1) = &20a1
    assert (sub_c20a5 - 1) = &20a4
    assert (sub_c20b7 - 1) = &20b6
    assert (sub_c20ba - 1) = &20b9
    assert (sub_c20c3 - 1) = &20c2
    assert (sub_c20c6 - 1) = &20c5

endsection

; Label references by decreasing frequency:
;     return_1:    4
;     l0080:       2
;     l0000:       1
;     l0070:       1
;     l0071:       1
;     l0072:       1
;     l0073:       1
;     l0074:       1
;     l0075:       1
;     l0081:       1
;     l2049:       1
;     l204a:       1
;     l207d:       1
;     l207e:       1
;     l2083:       1
;     l2087:       1
;     l208b:       1
;     l208d:       1
;     l208f:       1
;     l2090:       1
;     l2097:       1
;     l2098:       1
;     l209c:       1
;     sub_c2013:   1
;     sub_c2024:   1
;     sub_c2036:   1
;     sub_c204c:   1
;     sub_c2061:   1
;     sub_c206e:   1
;     table6:      1

; Automatically generated labels:
;     c2048
;     l0000
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0075
;     l0080
;     l0081
;     l2049
;     l204a
;     l207d
;     l207e
;     l2083
;     l2087
;     l208b
;     l208d
;     l208f
;     l2090
;     l2097
;     l2098
;     l209c
;     return_1
;     sub_c2013
;     sub_c2024
;     sub_c2036
;     sub_c204c
;     sub_c2061
;     sub_c206e
;     sub_c209f
;     sub_c20a2
;     sub_c20a5
;     sub_c20a8
;     sub_c20ab
;     sub_c20ae
;     sub_c20b1
;     sub_c20b4
;     sub_c20b7
;     sub_c20ba
;     sub_c20c3
;     sub_c20c6

; Stats:
;
;     Total size (Code + Data) = 201 bytes
;     Code                     = 161 bytes (80%)
;     Data                     = 40 bytes (20%)
;
;     Number of instructions   = 87
;     Number of data bytes     = 26 bytes
;     Number of data words     = 14 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
