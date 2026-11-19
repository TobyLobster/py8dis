; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071
l0072   = $0072
l0073   = $0073
l0074   = $0074
l0075   = $0075
l0076   = $0076
l0077   = $0077
l0080   = $0080
l0090   = $0090
l0091   = $0091
l0092   = $0092
l0093   = $0093

; Other
l0400   = $0400

    * = $2000

pydis_start
start
    jsr sub_c201c                                                     ; 2000: 20 1c 20     .
    jsr sub_c2029                                                     ; 2003: 20 29 20     )
    jsr sub_c2035                                                     ; 2006: 20 35 20     5
    jsr sub_c203e                                                     ; 2009: 20 3e 20     >
    jsr sub_c204a                                                     ; 200c: 20 4a 20     J
    jsr sub_c2057                                                     ; 200f: 20 57 20     W
    jsr sub_c206b                                                     ; 2012: 20 6b 20     k
    jsr sub_c2080                                                     ; 2015: 20 80 20     .
    jsr sub_c2089                                                     ; 2018: 20 89 20     .
    rts                                                               ; 201b: 60          `

; $201c referenced 1 time by $2000
sub_c201c
    lda l0070                                                         ; 201c: a5 70       .p
    cmp #8                                                            ; 201e: c9 08       ..
    bcs return_1                                                      ; 2020: b0 06       ..
    tax                                                               ; 2022: aa          .
    lda l208f,x                                                       ; 2023: bd 8f 20    ..
    sta l0080                                                         ; 2026: 85 80       ..
; $2028 referenced 1 time by $2020
return_1
    rts                                                               ; 2028: 60          `

; Copy 12 bytes of memory from l2097 to l0400
; $2029 referenced 1 time by $2003
sub_c2029
    ldx #$0b                                                          ; 2029: a2 0b       ..
; $202b referenced 1 time by $2032
loop_c202b
    lda l2097,x                                                       ; 202b: bd 97 20    ..
    sta l0400,x                                                       ; 202e: 9d 00 04    ...
    dex                                                               ; 2031: ca          .
    bpl loop_c202b                                                    ; 2032: 10 f7       ..
    rts                                                               ; 2034: 60          `

; $2035 referenced 1 time by $2006
sub_c2035
    lda l0071                                                         ; 2035: a5 71       .q
    and #$0f                                                          ; 2037: 29 0f       ).
    tax                                                               ; 2039: aa          .
    lda l20a3,x                                                       ; 203a: bd a3 20    ..
    rts                                                               ; 203d: 60          `

; $203e referenced 1 time by $2009
sub_c203e
    lda l0072                                                         ; 203e: a5 72       .r
    and #3                                                            ; 2040: 29 03       ).
    tax                                                               ; 2042: aa          .
    lda l20b3,x                                                       ; 2043: bd b3 20    ..
    ldy l20b6,x                                                       ; 2046: bc b6 20    ..
    rts                                                               ; 2049: 60          `

; $204a referenced 1 time by $200c
sub_c204a
    lda l0073                                                         ; 204a: a5 73       .s
    and #3                                                            ; 204c: 29 03       ).
    asl a                                                             ; 204e: 0a          .
    tax                                                               ; 204f: aa          .
    lda l20ba,x                                                       ; 2050: bd ba 20    ..
    ldy l20bb,x                                                       ; 2053: bc bb 20    ..
    rts                                                               ; 2056: 60          `

; $2057 referenced 1 time by $200f
sub_c2057
    lda l0074                                                         ; 2057: a5 74       .t
    and #3                                                            ; 2059: 29 03       ).
    tax                                                               ; 205b: aa          .
    lda l20c2,x                                                       ; 205c: bd c2 20    ..
    sta l0090                                                         ; 205f: 85 90       ..
    lda l20c6,x                                                       ; 2061: bd c6 20    ..
    sta l0091                                                         ; 2064: 85 91       ..
    ldy #0                                                            ; 2066: a0 00       ..
    lda (l0090),y                                                     ; 2068: b1 90       ..
    rts                                                               ; 206a: 60          `

; $206b referenced 1 time by $2012
sub_c206b
    lda l0075                                                         ; 206b: a5 75       .u
    and #1                                                            ; 206d: 29 01       ).
    asl a                                                             ; 206f: 0a          .
    tax                                                               ; 2070: aa          .
    lda l20ca,x                                                       ; 2071: bd ca 20    ..
    sta l0092                                                         ; 2074: 85 92       ..
    lda l20cb,x                                                       ; 2076: bd cb 20    ..
    sta l0093                                                         ; 2079: 85 93       ..
    ldy #0                                                            ; 207b: a0 00       ..
    lda (l0092),y                                                     ; 207d: b1 92       ..
    rts                                                               ; 207f: 60          `

; $2080 referenced 1 time by $2015
sub_c2080
    lda l0076                                                         ; 2080: a5 76       .v
    and #3                                                            ; 2082: 29 03       ).
    tax                                                               ; 2084: aa          .
    lda table8,x                                                      ; 2085: bd ce 20    ..
    rts                                                               ; 2088: 60          `

; $2089 referenced 1 time by $2018
sub_c2089
    ldx l0077                                                         ; 2089: a6 77       .w
    lda l20d2,x                                                       ; 208b: bd d2 20    ..
    rts                                                               ; 208e: 60          `

; A table of 8 bytes, indexed by X (0 to 7), read at $2023
; $208f referenced 1 time by $2023
l208f
    .byte $10, $4f, $4e, $5b, 0, $ff, $80, 1                          ; 208f: 10 4f 4e... .ON
; A table of 12 bytes, indexed by X (0 to 11), read at $202b
; $2097 referenced 1 time by $202b
l2097
    .byte 1, 2, 3, 4, 5, 6, 7, 8, 9, $0a, $0b, $0c                    ; 2097: 01 02 03... ...
; A table of 16 bytes, indexed by X (0 to 15), read at $203a
; $20a3 referenced 1 time by $203a
l20a3
    .text "0123456789ABCDEF"                                          ; 20a3: 30 31 32... 012
; A table of 4 bytes, indexed by X (0 to 3), read at $2043
; $20b3 referenced 1 time by $2043
l20b3
    .byte $11, $22, $33                                               ; 20b3: 11 22 33    ."3
; A table of 4 bytes, indexed by X (0 to 3), read at $2046
; $20b6 referenced 1 time by $2046
l20b6
    .byte $44, $55, $66, $77                                          ; 20b6: 44 55 66... DUf
; A table of 4 words, indexed by X (0, 2, 4 or 6), the low bytes read at $2050, and the high bytes read at $2053
; $20ba referenced 1 time by $2050
l20ba
l20bb = l20ba+1
    .word $1234, $5678, $9abc, $def0                                  ; 20ba: 34 12 78... 4.x
; $20bb referenced 1 time by $2053
; The low bytes of a table of 4 pointers (for the LDA at $2068)
; $20c2 referenced 1 time by $205c
l20c2
    .byte <l20d6                                                      ; 20c2: d6          .
    .byte <l20db                                                      ; 20c3: db          .
    .byte <l20df                                                      ; 20c4: df          .
    .byte <l20e3                                                      ; 20c5: e3          .
; The high bytes of the table of pointers
; $20c6 referenced 1 time by $2061
l20c6
    .byte >l20d6                                                      ; 20c6: 20
    .byte >l20db                                                      ; 20c7: 20
    .byte >l20df                                                      ; 20c8: 20
    .byte >l20e3                                                      ; 20c9: 20
; A table of 2 pointers (for the LDA at $207d)
; $20ca referenced 1 time by $2071
l20ca
l20cb = l20ca+1
    .word l20d6                                                       ; 20ca: d6 20       .
; $20cb referenced 1 time by $2076
    .word l20df                                                       ; 20cc: df 20       .
; $20ce referenced 1 time by $2085
table8
    .byte $de, $ad, $be, $ef                                          ; 20ce: de ad be... ...
; $20d2 referenced 1 time by $208b
l20d2
    .byte $81, $82, $83, $84                                          ; 20d2: 81 82 83... ...
l20d6
    .text "ZERO"                                                      ; 20d6: 5a 45 52... ZER
    .byte 0                                                           ; 20da: 00          .
l20db
    .text "ONE"                                                       ; 20db: 4f 4e 45    ONE
    .byte 0                                                           ; 20de: 00          .
l20df
    .text "TWO"                                                       ; 20df: 54 57 4f    TWO
    .byte 0                                                           ; 20e2: 00          .
l20e3
    .text "THREE"                                                     ; 20e3: 54 48 52... THR
    .byte 0                                                           ; 20e8: 00          .
pydis_end

.cerror (<l20d6) != $d6, "Assertion failed: <l20d6 == $d6"
.cerror (<l20db) != $db, "Assertion failed: <l20db == $db"
.cerror (<l20df) != $df, "Assertion failed: <l20df == $df"
.cerror (<l20e3) != $e3, "Assertion failed: <l20e3 == $e3"
.cerror (>l20d6) != $20, "Assertion failed: >l20d6 == $20"
.cerror (>l20db) != $20, "Assertion failed: >l20db == $20"
.cerror (>l20df) != $20, "Assertion failed: >l20df == $20"
.cerror (>l20e3) != $20, "Assertion failed: >l20e3 == $20"
.cerror (l20d6) != $20d6, "Assertion failed: l20d6 == $20d6"
.cerror (l20df) != $20df, "Assertion failed: l20df == $20df"

; Label references by decreasing frequency:
;     l0090:        2
;     l0092:        2
;     l0070:        1
;     l0071:        1
;     l0072:        1
;     l0073:        1
;     l0074:        1
;     l0075:        1
;     l0076:        1
;     l0077:        1
;     l0080:        1
;     l0091:        1
;     l0093:        1
;     l0400:        1
;     l208f:        1
;     l2097:        1
;     l20a3:        1
;     l20b3:        1
;     l20b6:        1
;     l20ba:        1
;     l20bb:        1
;     l20c2:        1
;     l20c6:        1
;     l20ca:        1
;     l20cb:        1
;     l20d2:        1
;     loop_c202b:   1
;     return_1:     1
;     sub_c201c:    1
;     sub_c2029:    1
;     sub_c2035:    1
;     sub_c203e:    1
;     sub_c204a:    1
;     sub_c2057:    1
;     sub_c206b:    1
;     sub_c2080:    1
;     sub_c2089:    1
;     table8:       1

; Automatically generated labels:
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0075
;     l0076
;     l0077
;     l0080
;     l0090
;     l0091
;     l0092
;     l0093
;     l0400
;     l208f
;     l2097
;     l20a3
;     l20b3
;     l20b6
;     l20ba
;     l20bb
;     l20c2
;     l20c6
;     l20ca
;     l20cb
;     l20d2
;     l20d6
;     l20db
;     l20df
;     l20e3
;     loop_c202b
;     return_1
;     sub_c201c
;     sub_c2029
;     sub_c2035
;     sub_c203e
;     sub_c204a
;     sub_c2057
;     sub_c206b
;     sub_c2080
;     sub_c2089

; Stats:
;
;     Total size (Code + Data) = 233 bytes
;     Code                     = 143 bytes (61%)
;     Data                     = 90 bytes (39%)
;
;     Number of instructions   = 70
;     Number of data bytes     = 47 bytes
;     Number of data words     = 12 bytes
;     Number of string bytes   = 31 bytes
;     Number of strings        = 5

