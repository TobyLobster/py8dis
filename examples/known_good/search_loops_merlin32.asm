; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0070   equ $70
l0071   equ $71
l0072   equ $72
l0073   equ $73
l0074   equ $74
l0075   equ $75
l0076   equ $76
l0077   equ $77
l0078   equ $78
l0079   equ $79
l007a   equ $7a
l007b   equ $7b
l0080   equ $80
l0081   equ $81
l0090   equ $90
l00a0   equ $a0

; 6502 vectors ($fffa-$ffff)
lffff   equ $ffff

    org $2000

pydis_start
start
    lda l0070                                                         ; 2000: a5 70       .p
    ldx #0                                                            ; 2002: a2 00       ..
    ; Search 16 bytes from key_table for A
; $2004 referenced 1 time by $200c
loop_c2004
    cmp key_table,x                                                   ; 2004: dd a3 20    ..
    beq c200e                                                         ; 2007: f0 05       ..
    inx                                                               ; 2009: e8          .
    cpx #$10                                                          ; 200a: e0 10       ..
    bne loop_c2004                                                    ; 200c: d0 f6       ..
; $200e referenced 1 time by $2007
c200e
    lda l0071                                                         ; 200e: a5 71       .q
    ldx #5                                                            ; 2010: a2 05       ..
    ; Search 6 bytes from table2 for A
; $2012 referenced 1 time by $2018
loop_c2012
    cmp table2,x                                                      ; 2012: dd b3 20    ..
    beq c201a                                                         ; 2015: f0 03       ..
    dex                                                               ; 2017: ca          .
    bpl loop_c2012                                                    ; 2018: 10 f8       ..
; $201a referenced 1 time by $2015
c201a
    ldx #0                                                            ; 201a: a2 00       ..
    ; Search 256 bytes from string3 for 0
; $201c referenced 1 time by $2022
loop_c201c
    lda string3,x                                                     ; 201c: bd 00 22    .."
    beq c2024                                                         ; 201f: f0 03       ..
    inx                                                               ; 2021: e8          .
    bne loop_c201c                                                    ; 2022: d0 f8       ..
; $2024 referenced 1 time by $201f
c2024
    ldy #0                                                            ; 2024: a0 00       ..
    ; Search 40 bytes from buffer4 for a byte other than $20
; $2026 referenced 1 time by $2030
loop_c2026
    lda buffer4,y                                                     ; 2026: b9 00 23    ..#
    cmp #$20 ; ' '                                                    ; 2029: c9 20       .
    bne c2032                                                         ; 202b: d0 05       ..
    iny                                                               ; 202d: c8          .
    cpy #$28 ; '('                                                    ; 202e: c0 28       .(
    bcc loop_c2026                                                    ; 2030: 90 f4       ..
; $2032 referenced 1 time by $202b
c2032
    lda #<text5                                                       ; 2032: a9 28       .(
    sta l0080                                                         ; 2034: 85 80       ..
    lda #>text5                                                       ; 2036: a9 23       .#
    sta l0081                                                         ; 2038: 85 81       ..
    ldy #0                                                            ; 203a: a0 00       ..
    ; Search 256 bytes from text5 for $0d
; $203c referenced 1 time by $2043
loop_c203c
    lda (l0080),y                                                     ; 203c: b1 80       ..
    cmp #$0d                                                          ; 203e: c9 0d       ..
    beq c2045                                                         ; 2040: f0 03       ..
    iny                                                               ; 2042: c8          .
    bne loop_c203c                                                    ; 2043: d0 f7       ..
; $2045 referenced 1 time by $2040
c2045
    lda l0072                                                         ; 2045: a5 72       .r
    ldx l0073                                                         ; 2047: a6 73       .s
    ; Search from table6+X to table6 + 7 for A
; $2049 referenced 1 time by $2051
loop_c2049
    cmp table6,x                                                      ; 2049: dd b9 20    ..
    beq c2053                                                         ; 204c: f0 05       ..
    inx                                                               ; 204e: e8          .
    cpx #8                                                            ; 204f: e0 08       ..
    bne loop_c2049                                                    ; 2051: d0 f6       ..
; $2053 referenced 1 time by $204c
c2053
    ldx l0074                                                         ; 2053: a6 74       .t
    ; Search X bytes from table7 + 1 for 0
; $2055 referenced 1 time by $205b
loop_c2055
    lda table7,x                                                      ; 2055: bd c1 20    ..
    beq c205d                                                         ; 2058: f0 03       ..
    dex                                                               ; 205a: ca          .
    bne loop_c2055                                                    ; 205b: d0 f8       ..
; $205d referenced 1 time by $2058
c205d
    ldx #$10                                                          ; 205d: a2 10       ..
    ; Clear 16 bytes of memory from table8 onwards
; $205f referenced 1 time by $2063
loop_c205f
    stz table8 - 1,x                                                  ; 205f: 9e 27 24    .'$
    dex                                                               ; 2062: ca          .
    bne loop_c205f                                                    ; 2063: d0 fa       ..
    ldx #0                                                            ; 2065: a2 00       ..
    ; Clear 8 bytes of memory from l0090 onwards, and 8 bytes from table9 onwards
; $2067 referenced 1 time by $206f
loop_c2067
    stz l0090,x                                                       ; 2067: 74 90       t.
    stz table9,x                                                      ; 2069: 9e 38 24    .8$
    inx                                                               ; 206c: e8          .
    cpx #8                                                            ; 206d: e0 08       ..
    bne loop_c2067                                                    ; 206f: d0 f6       ..
    ldx l0075                                                         ; 2071: a6 75       .u
    ; Clear X+1 bytes of memory from l00a0 onwards
; $2073 referenced 1 time by $2076
loop_c2073
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
loop_c2086
l2087 equ loop_c2086+1
l2088 equ loop_c2086+2
    cmp lffff,x                                                       ; 2086: dd ff ff    ...
; $2087 referenced 1 time by $207a
; $2088 referenced 1 time by $207f
    beq c208e                                                         ; 2089: f0 03       ..
    dex                                                               ; 208b: ca          .
    bpl loop_c2086                                                    ; 208c: 10 f8       ..
; $208e referenced 1 time by $2089
c208e
    lda l007a                                                         ; 208e: a5 7a       .z
    ldx #0                                                            ; 2090: a2 00       ..
    bit l007b                                                         ; 2092: 24 7b       ${
    bmi c2098                                                         ; 2094: 30 02       0.
    ldx #2                                                            ; 2096: a2 02       ..
; $2098 referenced 2 times by $2094, $20a0
c2098
    cmp table2,x                                                      ; 2098: dd b3 20    ..
    beq return_1                                                      ; 209b: f0 05       ..
    inx                                                               ; 209d: e8          .
    cpx #6                                                            ; 209e: e0 06       ..
    bne c2098                                                         ; 20a0: d0 f6       ..
; $20a2 referenced 1 time by $209b
return_1
    rts                                                               ; 20a2: 60          `

; A table of 16 bytes, indexed by X (0 to 15), read at $2004
; $20a3 referenced 1 time by $2004
key_table
    dfb 1, 2, 3, 4, 5, 6, 7, 8, 9, $0a, $0b, $0c, $0d, $0e, $0f, $10  ; 20a3: 01 02 03... ...
; A table of 6 bytes, indexed by X (0 to 5), read at $2012 and $2098
; $20b3 referenced 2 times by $2012, $2098
table2
    dfb $20, $21, $22, $23, $24, $25                                  ; 20b3: 20 21 22...  !"
; $20b9 referenced 1 time by $2049
table6
    asc '01234567'                                                    ; 20b9: 30 31 32... 012
; $20c1 referenced 1 time by $2055
table7
    dfb 0                                                             ; 20c1: 00          .
    asc 'ABCD'                                                        ; 20c2: 41 42 43... ABC
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 20c6: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 20db: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 20f0: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 2105: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 211a: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 212f: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 2144: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 2159: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 216e: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 2183: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 2198: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 21ad: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 21c2: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; 21d7: 00 00 00... ...
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0    ; 21ec: 00 00 00... ...
; $2200 referenced 1 time by $201c
string3
    asc 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' ; 2200: 55 55 55... UUU
    asc 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' ; 223b: 55 55 55... UUU
    asc 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' ; 2276: 55 55 55... UUU
    asc 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU' ; 22b1: 55 55 55... UUU
    asc 'UUUUUUUUUUUUUUUUUUUU'                                        ; 22ec: 55 55 55... UUU
; A table of 40 bytes, indexed by Y (0 to 39), read at $2026
; $2300 referenced 1 time by $2026
buffer4
    dfb $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20    ; 2300: 20 20 20...
    dfb $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20    ; 230c: 20 20 20...
    dfb $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20    ; 2318: 20 20 20...
    dfb $20, $20, $20, $20                                            ; 2324: 20 20 20...
text5
    asc 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' ; 2328: 66 66 66... fff
    asc 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' ; 2363: 66 66 66... fff
    asc 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' ; 239e: 66 66 66... fff
    asc 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' ; 23d9: 66 66 66... fff
    asc 'fffffffffffffffffff'                                         ; 2414: 66 66 66... fff
; $2427 referenced 1 time by $205f
    dfb $66                                                           ; 2427: 66          f
; A table of 16 bytes, indexed by X (1 to 16), written at $205f
table8
    asc 'wwwwwwwwwwwwwwww'                                            ; 2428: 77 77 77... www
; A table of 8 bytes, indexed by X (0 to 7), written at $2069
; $2438 referenced 1 time by $2069
table9
    dfb $88, $88, $88, $88, $88, $88, $88, $88                        ; 2438: 88 88 88... ...
pydis_end

    err text5 & $ff - $28
    err text5 & $ffff / $0100 - $23
    err table8 - 1 - $2427

; Label references by decreasing frequency:
;     c2098:        2
;     l0080:        2
;     table2:       2
;     buffer4:      1
;     c200e:        1
;     c201a:        1
;     c2024:        1
;     c2032:        1
;     c2045:        1
;     c2053:        1
;     c205d:        1
;     c208e:        1
;     key_table:    1
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
;     l0081:        1
;     l0090:        1
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
;     return_1:     1
;     string3:      1
;     table6:       1
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
;     l0080
;     l0081
;     l0090
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
;     return_1

; Stats:
;
;     Total size (Code + Data) = 1088 bytes
;     Code                     = 163 bytes (15%)
;     Data                     = 925 bytes (85%)
;
;     Number of instructions   = 82
;     Number of data bytes     = 386 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 539 bytes
;     Number of strings        = 5
