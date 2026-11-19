; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071
l0072   = $0072
l0074   = $0074
l0076   = $0076

    * = $2000

pydis_start
start
    jsr sub_c2013                                                     ; 2000: 20 13 20     .
    jsr sub_c2025                                                     ; 2003: 20 25 20     %
    jsr sub_c2031                                                     ; 2006: 20 31 20     1
    jsr sub_c203c                                                     ; 2009: 20 3c 20     <
    jsr sub_c2047                                                     ; 200c: 20 47 20     G
    jsr sub_c2050                                                     ; 200f: 20 50 20     P
    rts                                                               ; 2012: 60          `

; $2013 referenced 1 time by $2000
sub_c2013
    ldy #$11                                                          ; 2013: a0 11       ..
    lda l0070                                                         ; 2015: a5 70       .p
    clc                                                               ; 2017: 18          .
    adc l0071                                                         ; 2018: 65 71       eq
    sta l0072                                                         ; 201a: 85 72       .r
    lda #1                                                            ; 201c: a9 01       ..
    sta (l0074),y                                                     ; 201e: 91 74       .t  ; Offset Y=$11
    ldy #0                                                            ; 2020: a0 00       ..
    lda (l0074),y                                                     ; 2022: b1 74       .t
    rts                                                               ; 2024: 60          `

; $2025 referenced 1 time by $2003
sub_c2025
    ldy #0                                                            ; 2025: a0 00       ..
    tya                                                               ; 2027: 98          .   ; A=0
    ; Clear 16 bytes of memory from table1 onwards
; $2028 referenced 1 time by $202e
loop_c2028
    sta table1,y                                                      ; 2028: 99 59 20    .Y  ; A=0
    iny                                                               ; 202b: c8          .
    cpy #$10                                                          ; 202c: c0 10       ..
    bne loop_c2028                                                    ; 202e: d0 f8       ..
    rts                                                               ; 2030: 60          `

; $2031 referenced 1 time by $2006
sub_c2031
    lda #$ff                                                          ; 2031: a9 ff       ..
    ldx #7                                                            ; 2033: a2 07       ..
    ; Set 8 bytes of memory from table2 onwards to 255
; $2035 referenced 1 time by $2039
loop_c2035
    sta table2,x                                                      ; 2035: 9d 69 20    .i  ; A=$ff
    dex                                                               ; 2038: ca          .
    bpl loop_c2035                                                    ; 2039: 10 fa       ..
    rts                                                               ; 203b: 60          `

; $203c referenced 1 time by $2009
sub_c203c
    lda #0                                                            ; 203c: a9 00       ..
    ldy #4                                                            ; 203e: a0 04       ..
    ; Clear 4 bytes of memory from l2072 onwards
; $2040 referenced 1 time by $2044
loop_c2040
    sta l2072 - 1,y                                                   ; 2040: 99 71 20    .q  ; A=0
    dey                                                               ; 2043: 88          .
    bne loop_c2040                                                    ; 2044: d0 fa       ..
    rts                                                               ; 2046: 60          `

; $2047 referenced 1 time by $200c
sub_c2047
    lda #0                                                            ; 2047: a9 00       ..
    tay                                                               ; 2049: a8          .   ; Y=0
    ; Clear 256 bytes of memory from (l0074) onwards
; $204a referenced 1 time by $204d
loop_c204a
    sta (l0074),y                                                     ; 204a: 91 74       .t  ; A=0
    iny                                                               ; 204c: c8          .
    bne loop_c204a                                                    ; 204d: d0 fb       ..
    rts                                                               ; 204f: 60          `

; $2050 referenced 1 time by $200f
sub_c2050
    lda l0076                                                         ; 2050: a5 76       .v
    sta l2056                                                         ; 2052: 8d 56 20    .V
c2055
l2056 = c2055+1
    ldx #0                                                            ; 2055: a2 00       ..
; $2056 referenced 1 time by $2052
    txa                                                               ; 2057: 8a          .
    rts                                                               ; 2058: 60          `

; A table of 16 bytes, indexed by Y (0 to 15), written at $2028
; $2059 referenced 1 time by $2028
table1
    .byte $11, $11, $11, $11, $11, $11, $11, $11, $11, $11, $11, $11  ; 2059: 11 11 11... ...
    .byte $11, $11, $11, $11                                          ; 2065: 11 11 11... ...
; A table of 8 bytes, indexed by X (0 to 7), written at $2035
; $2069 referenced 1 time by $2035
table2
    .byte $22, $22, $22, $22, $22, $22, $22, $22                      ; 2069: 22 22 22... """
; $2071 referenced 1 time by $2040
table3
    .byte $33                                                         ; 2071: 33          3
; A table of 4 bytes, indexed by Y (1 to 4), written at $2040
l2072
    .byte $33, $33, $33, $33                                          ; 2072: 33 33 33... 333
pydis_end

.cerror (l2072 - 1) != $2071, "Assertion failed: l2072 - 1 == $2071"

; Label references by decreasing frequency:
;     l0074:        3
;     l0070:        1
;     l0071:        1
;     l0072:        1
;     l0076:        1
;     l2056:        1
;     loop_c2028:   1
;     loop_c2035:   1
;     loop_c2040:   1
;     loop_c204a:   1
;     sub_c2013:    1
;     sub_c2025:    1
;     sub_c2031:    1
;     sub_c203c:    1
;     sub_c2047:    1
;     sub_c2050:    1
;     table1:       1
;     table2:       1
;     table3:       1

; Automatically generated labels:
;     c2055
;     l0070
;     l0071
;     l0072
;     l0074
;     l0076
;     l2056
;     l2072
;     loop_c2028
;     loop_c2035
;     loop_c2040
;     loop_c204a
;     sub_c2013
;     sub_c2025
;     sub_c2031
;     sub_c203c
;     sub_c2047
;     sub_c2050

; Stats:
;
;     Total size (Code + Data) = 118 bytes
;     Code                     = 89 bytes (75%)
;     Data                     = 29 bytes (25%)
;
;     Number of instructions   = 47
;     Number of data bytes     = 29 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

