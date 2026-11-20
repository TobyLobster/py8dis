; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .setcpu "65C02"

; Memory locations

; Zero page ($0000-$00ff)
l0060   = $0060
l0061   = $0061
l0070   = $0070
l0071   = $0071
l0072   = $0072
l0073   = $0073
l0074   = $0074
l0075   = $0075
l0076   = $0076
l0077   = $0077
l0078   = $0078
l0079   = $0079
l007a   = $007a
l007b   = $007b
l007c   = $007c
l007d   = $007d
l007e   = $007e
l007f   = $007f
l0080   = $0080
l0081   = $0081
l0082   = $0082
l0083   = $0083
l008f   = $008f
l0090   = $0090
l0093   = $0093
l0094   = $0094
l00a0   = $00a0

; 6502 vectors ($fffa-$ffff)
lffff   = $ffff

    .org $2000

pydis_start:
start:
    lda l0070                                                         ; 2000: a5 70       .p
    ldx #0                                                            ; 2002: a2 00       ..
    ; Search 16 bytes from key_table for A
; $2004 referenced 1 time by $200c
loop_c2004:
    cmp key_table,x                                                   ; 2004: dd 1f 21    ..!
    beq c200e                                                         ; 2007: f0 05       ..
    inx                                                               ; 2009: e8          .
    cpx #$10                                                          ; 200a: e0 10       ..
    bne loop_c2004                                                    ; 200c: d0 f6       ..
; $200e referenced 1 time by $2007
c200e:
    lda l0071                                                         ; 200e: a5 71       .q
    ldx #5                                                            ; 2010: a2 05       ..
    ; Search 6 bytes from table2 for A
; $2012 referenced 1 time by $2018
loop_c2012:
    cmp table2,x                                                      ; 2012: dd 2f 21    ./!
    beq c201a                                                         ; 2015: f0 03       ..
    dex                                                               ; 2017: ca          .
    bpl loop_c2012                                                    ; 2018: 10 f8       ..
; $201a referenced 1 time by $2015
c201a:
    ldx #0                                                            ; 201a: a2 00       ..
    ; Search 256 bytes from string3 for 0
; $201c referenced 1 time by $2022
loop_c201c:
    lda string3,x                                                     ; 201c: bd 00 22    .."
    beq c2024                                                         ; 201f: f0 03       ..
    inx                                                               ; 2021: e8          .
    bne loop_c201c                                                    ; 2022: d0 f8       ..
; $2024 referenced 1 time by $201f
c2024:
    ldy #0                                                            ; 2024: a0 00       ..
    ; Search 40 bytes from buffer4 for a byte other than $20
; $2026 referenced 1 time by $2030
loop_c2026:
    lda buffer4,y                                                     ; 2026: b9 00 23    ..#
    cmp #$20 ; ' '                                                    ; 2029: c9 20       .
    bne c2032                                                         ; 202b: d0 05       ..
    iny                                                               ; 202d: c8          .
    cpy #$28 ; '('                                                    ; 202e: c0 28       .(
    bcc loop_c2026                                                    ; 2030: 90 f4       ..
; $2032 referenced 1 time by $202b
c2032:
    lda #<text5                                                       ; 2032: a9 28       .(
    sta l0080                                                         ; 2034: 85 80       ..
    lda #>text5                                                       ; 2036: a9 23       .#
    sta l0081                                                         ; 2038: 85 81       ..
    ldy #0                                                            ; 203a: a0 00       ..
    ; Search 256 bytes from text5 for $0d
; $203c referenced 1 time by $2043
loop_c203c:
    lda (l0080),y                                                     ; 203c: b1 80       ..
    cmp #$0d                                                          ; 203e: c9 0d       ..
    beq c2045                                                         ; 2040: f0 03       ..
    iny                                                               ; 2042: c8          .
    bne loop_c203c                                                    ; 2043: d0 f7       ..
; $2045 referenced 1 time by $2040
c2045:
    lda l0072                                                         ; 2045: a5 72       .r
    ldx l0073                                                         ; 2047: a6 73       .s
    ; Search from table6+X to table6 + 7 for A
; $2049 referenced 1 time by $2051
loop_c2049:
    cmp table6,x                                                      ; 2049: dd 35 21    .5!
    beq c2053                                                         ; 204c: f0 05       ..
    inx                                                               ; 204e: e8          .
    cpx #8                                                            ; 204f: e0 08       ..
    bne loop_c2049                                                    ; 2051: d0 f6       ..
; $2053 referenced 1 time by $204c
c2053:
    ldx l0074                                                         ; 2053: a6 74       .t
    ; Search X bytes from table7 + 1 for 0
; $2055 referenced 1 time by $205b
loop_c2055:
    lda table7,x                                                      ; 2055: bd 3d 21    .=!
    beq c205d                                                         ; 2058: f0 03       ..
    dex                                                               ; 205a: ca          .
    bne loop_c2055                                                    ; 205b: d0 f8       ..
; $205d referenced 1 time by $2058
c205d:
    ldx #$10                                                          ; 205d: a2 10       ..
    ; Clear 16 bytes of memory from table8 onwards
; $205f referenced 1 time by $2063
loop_c205f:
    stz table8 - 1,x                                                  ; 205f: 9e 27 24    .'$
    dex                                                               ; 2062: ca          .
    bne loop_c205f                                                    ; 2063: d0 fa       ..
    ldx #0                                                            ; 2065: a2 00       ..
    ; Clear 8 bytes of memory from l0090 onwards, and 8 bytes from table9 onwards
; $2067 referenced 1 time by $206f
loop_c2067:
    stz l0090,x                                                       ; 2067: 74 90       t.
    stz table9,x                                                      ; 2069: 9e 38 24    .8$
    inx                                                               ; 206c: e8          .
    cpx #8                                                            ; 206d: e0 08       ..
    bne loop_c2067                                                    ; 206f: d0 f6       ..
    ldx l0075                                                         ; 2071: a6 75       .u
    ; Clear X+1 bytes of memory from l00a0 onwards
; $2073 referenced 1 time by $2076
loop_c2073:
    stz l00a0,x                                                       ; 2073: 74 a0       t.
    dex                                                               ; 2075: ca          .
    bpl loop_c2073                                                    ; 2076: 10 fb       ..
    lda l0076                                                         ; 2078: a5 76       .v
    sta l2087                                                         ; 207a: 8d 87 20    ..
    lda l0077                                                         ; 207d: a5 77       .w
    sta l2088                                                         ; 207f: 8d 88 20    ..
    lda l0078                                                         ; 2082: a5 78       .x
    ldx l0079                                                         ; 2084: a6 79       .y
    ; Search X+1 bytes from the address in l2087 for A
; $2086 referenced 1 time by $208c
loop_c2086:
l2087 = loop_c2086+1
l2088 = loop_c2086+2
    cmp lffff,x                                                       ; 2086: dd ff ff    ...
; $2087 referenced 1 time by $207a
; $2088 referenced 1 time by $207f
    beq c208e                                                         ; 2089: f0 03       ..
    dex                                                               ; 208b: ca          .
    bpl loop_c2086                                                    ; 208c: 10 f8       ..
; $208e referenced 1 time by $2089
c208e:
    lda l007a                                                         ; 208e: a5 7a       .z
    ldx #0                                                            ; 2090: a2 00       ..
    bit l007b                                                         ; 2092: 24 7b       ${
    bmi c2098                                                         ; 2094: 30 02       0.
    ldx #2                                                            ; 2096: a2 02       ..
; $2098 referenced 2 times by $2094, $20a0
c2098:
    cmp table2,x                                                      ; 2098: dd 2f 21    ./!
    beq c20a2                                                         ; 209b: f0 05       ..
    inx                                                               ; 209d: e8          .
    cpx #6                                                            ; 209e: e0 06       ..
    bne c2098                                                         ; 20a0: d0 f6       ..
; $20a2 referenced 1 time by $209b
c20a2:
    ldx #0                                                            ; 20a2: a2 00       ..
    ; Compare 4 bytes from table6 with key_table
; $20a4 referenced 1 time by $20af
loop_c20a4:
    lda table6,x                                                      ; 20a4: bd 35 21    .5!
    cmp key_table,x                                                   ; 20a7: dd 1f 21    ..!
    bne c20b1                                                         ; 20aa: d0 05       ..
    inx                                                               ; 20ac: e8          .
    cpx #4                                                            ; 20ad: e0 04       ..
    bne loop_c20a4                                                    ; 20af: d0 f3       ..
; $20b1 referenced 1 time by $20aa
c20b1:
    ldx #4                                                            ; 20b1: a2 04       ..
    ; Compare 4 bytes from l0090 with l0094
; $20b3 referenced 1 time by $20ba
loop_c20b3:
    lda l008f,x                                                       ; 20b3: b5 8f       ..
    eor l0093,x                                                       ; 20b5: 55 93       U.
    bne c20bc                                                         ; 20b7: d0 03       ..
    dex                                                               ; 20b9: ca          .
    bne loop_c20b3                                                    ; 20ba: d0 f7       ..
; $20bc referenced 1 time by $20b7
c20bc:
    lda l007c                                                         ; 20bc: a5 7c       .|
    sta l0082                                                         ; 20be: 85 82       ..
    lda l007d                                                         ; 20c0: a5 7d       .}
    sta l0083                                                         ; 20c2: 85 83       ..
    ldy #0                                                            ; 20c4: a0 00       ..
    ldx l007e                                                         ; 20c6: a6 7e       .~
    ; Compare X bytes from (l0082) with buffer4
; $20c8 referenced 1 time by $20d1
loop_c20c8:
    lda (l0082),y                                                     ; 20c8: b1 82       ..
    cmp buffer4,y                                                     ; 20ca: d9 00 23    ..#
    bne c20d3                                                         ; 20cd: d0 04       ..
    iny                                                               ; 20cf: c8          .
    dex                                                               ; 20d0: ca          .
    bne loop_c20c8                                                    ; 20d1: d0 f5       ..
; $20d3 referenced 1 time by $20cd
c20d3:
    lda l007f                                                         ; 20d3: a5 7f       ..
    ldx #3                                                            ; 20d5: a2 03       ..
    ldy #2                                                            ; 20d7: a0 02       ..
    ; Search 4 bytes from table2 + 2 for A
; $20d9 referenced 1 time by $20e0
loop_c20d9:
    cmp table2,y                                                      ; 20d9: d9 2f 21    ./!
    beq c20e2                                                         ; 20dc: f0 04       ..
    iny                                                               ; 20de: c8          .
    dex                                                               ; 20df: ca          .
    bpl loop_c20d9                                                    ; 20e0: 10 f7       ..
; $20e2 referenced 1 time by $20dc
c20e2:
    ldx #2                                                            ; 20e2: a2 02       ..
    ldy #5                                                            ; 20e4: a0 05       ..
    ; Search 3 bytes from table6 + 3 for 0
; $20e6 referenced 1 time by $20ed
loop_c20e6:
    lda table6,y                                                      ; 20e6: b9 35 21    .5!
    beq c20ef                                                         ; 20e9: f0 04       ..
    dey                                                               ; 20eb: 88          .
    dex                                                               ; 20ec: ca          .
    bpl loop_c20e6                                                    ; 20ed: 10 f7       ..
; $20ef referenced 1 time by $20e9
c20ef:
    ldy l0060                                                         ; 20ef: a4 60       .`
    ldx #3                                                            ; 20f1: a2 03       ..
    ; Compare 4 bytes from table6+Y-3 with key_table
; $20f3 referenced 1 time by $20fd
loop_c20f3:
    lda table6,y                                                      ; 20f3: b9 35 21    .5!
    cmp key_table,x                                                   ; 20f6: dd 1f 21    ..!
    bne c20ff                                                         ; 20f9: d0 04       ..
    dey                                                               ; 20fb: 88          .
    dex                                                               ; 20fc: ca          .
    bpl loop_c20f3                                                    ; 20fd: 10 f4       ..
; $20ff referenced 1 time by $20f9
c20ff:
    ldy #2                                                            ; 20ff: a0 02       ..
    ldx #3                                                            ; 2101: a2 03       ..
    ; Compare 4 bytes from table6 + 2 with key_table, in reverse
; $2103 referenced 1 time by $210d
loop_c2103:
    lda table6,y                                                      ; 2103: b9 35 21    .5!
    eor key_table,x                                                   ; 2106: 5d 1f 21    ].!
    bne c210f                                                         ; 2109: d0 04       ..
    iny                                                               ; 210b: c8          .
    dex                                                               ; 210c: ca          .
    bpl loop_c2103                                                    ; 210d: 10 f4       ..
; $210f referenced 1 time by $2109
c210f:
    ldy l0061                                                         ; 210f: a4 61       .a
    ldx #5                                                            ; 2111: a2 05       ..
; $2113 referenced 1 time by $211c
loop_c2113:
    lda (l0082),y                                                     ; 2113: b1 82       ..
    cmp table2,x                                                      ; 2115: dd 2f 21    ./!
    bne return_1                                                      ; 2118: d0 04       ..
    iny                                                               ; 211a: c8          .
    inx                                                               ; 211b: e8          .
    bne loop_c2113                                                    ; 211c: d0 f5       ..
; $211e referenced 1 time by $2118
return_1:
    rts                                                               ; 211e: 60          `

; A table of 16 bytes, indexed by X (0 to 15), read at $2004, $20a7, $20f6 and $2106
; $211f referenced 4 times by $2004, $20a7, $20f6, $2106
key_table:
    .byte   1, 2, 3, 4, 5, 6, 7, 8, 9, $0a, $0b, $0c, $0d, $0e, $0f   ; 211f: 01 02 03... ...
    .byte $10                                                         ; 212e: 10          .
; A table of 6 bytes, indexed by X (0 to 5), read at $2012 and $2098
; $212f referenced 4 times by $2012, $2098, $20d9, $2115
table2:
    .byte $20, $21, $22, $23, $24, $25                                ; 212f: 20 21 22...  !"
; A table of 4 bytes, indexed by X (0 to 3), read at $20a4
; $2135 referenced 5 times by $2049, $20a4, $20e6, $20f3, $2103
table6:
    .byte $30, $31, $32, $33                                          ; 2135: 30 31 32... 012
    .byte "4567"                                                      ; 2139: 34 35 36... 456
; $213d referenced 1 time by $2055
table7:
    .byte 0                                                           ; 213d: 00          .
    .byte "ABCD"                                                      ; 213e: 41 42 43... ABC
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2142: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2156: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 216a: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 217e: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2192: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 21a6: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 21ba: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 21ce: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 21e2: 00 00 00... ...
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                ; 21f6: 00 00 00... ...
; $2200 referenced 1 time by $201c
string3:
    .byte "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ; 2200: 55 55 55... UUU
    .byte "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ; 2239: 55 55 55... UUU
    .byte "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ; 2272: 55 55 55... UUU
    .byte "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ; 22ab: 55 55 55... UUU
    .byte "UUUUUUUUUUUUUUUUUUUUUUUUUUUU"                              ; 22e4: 55 55 55... UUU
; A table of 40 bytes, indexed by Y (0 to 39), read at $2026
; $2300 referenced 2 times by $2026, $20ca
buffer4:
    .byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20  ; 2300: 20 20 20...
    .byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20  ; 230c: 20 20 20...
    .byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20  ; 2318: 20 20 20...
    .byte $20, $20, $20, $20                                          ; 2324: 20 20 20...
text5:
    .byte "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ; 2328: 66 66 66... fff
    .byte "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ; 2361: 66 66 66... fff
    .byte "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ; 239a: 66 66 66... fff
    .byte "fffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ; 23d3: 66 66 66... fff
    .byte "fffffffffffffffffffffffffff"                               ; 240c: 66 66 66... fff
; $2427 referenced 1 time by $205f
    .byte $66                                                         ; 2427: 66          f
; A table of 16 bytes, indexed by X (1 to 16), written at $205f
table8:
    .byte "wwwwwwwwwwwwwwww"                                          ; 2428: 77 77 77... www
; A table of 8 bytes, indexed by X (0 to 7), written at $2069
; $2438 referenced 1 time by $2069
table9:
    .byte $88, $88, $88, $88, $88, $88, $88, $88                      ; 2438: 88 88 88... ...
pydis_end:

.assert (<text5) = $28, error, "Assertion failed: <text5 = $28"
.assert (>text5) = $23, error, "Assertion failed: >text5 = $23"
.assert (table8 - 1) = $2427, error, "Assertion failed: table8 - 1 = $2427"

; Label references by decreasing frequency:
;     table6:       5
;     key_table:    4
;     table2:       4
;     l0082:        3
;     buffer4:      2
;     c2098:        2
;     l0080:        2
;     c200e:        1
;     c201a:        1
;     c2024:        1
;     c2032:        1
;     c2045:        1
;     c2053:        1
;     c205d:        1
;     c208e:        1
;     c20a2:        1
;     c20b1:        1
;     c20bc:        1
;     c20d3:        1
;     c20e2:        1
;     c20ef:        1
;     c20ff:        1
;     c210f:        1
;     l0060:        1
;     l0061:        1
;     l0070:        1
;     l0071:        1
;     l0072:        1
;     l0073:        1
;     l0074:        1
;     l0075:        1
;     l0076:        1
;     l0077:        1
;     l0078:        1
;     l0079:        1
;     l007a:        1
;     l007b:        1
;     l007c:        1
;     l007d:        1
;     l007e:        1
;     l007f:        1
;     l0081:        1
;     l0083:        1
;     l008f:        1
;     l0090:        1
;     l0093:        1
;     l00a0:        1
;     l2087:        1
;     l2088:        1
;     lffff:        1
;     loop_c2004:   1
;     loop_c2012:   1
;     loop_c201c:   1
;     loop_c2026:   1
;     loop_c203c:   1
;     loop_c2049:   1
;     loop_c2055:   1
;     loop_c205f:   1
;     loop_c2067:   1
;     loop_c2073:   1
;     loop_c2086:   1
;     loop_c20a4:   1
;     loop_c20b3:   1
;     loop_c20c8:   1
;     loop_c20d9:   1
;     loop_c20e6:   1
;     loop_c20f3:   1
;     loop_c2103:   1
;     loop_c2113:   1
;     return_1:     1
;     string3:      1
;     table7:       1
;     table9:       1

; Automatically generated labels:
;     c200e
;     c201a
;     c2024
;     c2032
;     c2045
;     c2053
;     c205d
;     c208e
;     c2098
;     c20a2
;     c20b1
;     c20bc
;     c20d3
;     c20e2
;     c20ef
;     c20ff
;     c210f
;     l0060
;     l0061
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0075
;     l0076
;     l0077
;     l0078
;     l0079
;     l007a
;     l007b
;     l007c
;     l007d
;     l007e
;     l007f
;     l0080
;     l0081
;     l0082
;     l0083
;     l008f
;     l0090
;     l0093
;     l0094
;     l00a0
;     l2087
;     l2088
;     lffff
;     loop_c2004
;     loop_c2012
;     loop_c201c
;     loop_c2026
;     loop_c203c
;     loop_c2049
;     loop_c2055
;     loop_c205f
;     loop_c2067
;     loop_c2073
;     loop_c2086
;     loop_c20a4
;     loop_c20b3
;     loop_c20c8
;     loop_c20d9
;     loop_c20e6
;     loop_c20f3
;     loop_c2103
;     loop_c2113
;     return_1

; Stats:
;
;     Total size (Code + Data) = 1088 bytes
;     Code                     = 287 bytes (26%)
;     Data                     = 801 bytes (74%)
;
;     Number of instructions   = 146
;     Number of data bytes     = 266 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 535 bytes
;     Number of strings        = 5

