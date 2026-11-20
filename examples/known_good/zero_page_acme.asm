; Memory locations

; Zero page ($0000-$00ff)
l0070   = $70
l0071   = $71
l0072   = $72
l0073   = $73
l0074   = $74
l0075   = $75
l0076   = $76
l0077   = $77
l0078   = $78
l0079   = $79
l007a   = $7a
l007b   = $7b
l007c   = $7c
l007d   = $7d
l007e   = $7e
l0080   = $80
l0081   = $81
l0090   = $90
l0092   = $92

; Other
buffer  = $0400
buffer2 = $0500

    * = $2000

pydis_start
start
    jsr sub_c201f                                                     ; 2000: 20 1f 20     .
    jsr sub_c202f                                                     ; 2003: 20 2f 20     /
    jsr sub_c2044                                                     ; 2006: 20 44 20     D
    jsr sub_c2061                                                     ; 2009: 20 61 20     a
    jsr sub_c2085                                                     ; 200c: 20 85 20     .
    jsr sub_c209c                                                     ; 200f: 20 9c 20     .
    jsr sub_c20ad                                                     ; 2012: 20 ad 20     .
    jsr sub_c20b6                                                     ; 2015: 20 b6 20     .
    jsr sub_c20d7                                                     ; 2018: 20 d7 20     .
    jsr sub_c20e1                                                     ; 201b: 20 e1 20     .
    rts                                                               ; 201e: 60          `

; $201f referenced 1 time by $2000
sub_c201f
    lda l0070                                                         ; 201f: a5 70       .p
    ora #$80                                                          ; 2021: 09 80       ..
    sta l0071                                                         ; 2023: 85 71       .q
    lda #0                                                            ; 2025: a9 00       ..
    sta l0072                                                         ; 2027: 85 72       .r
    ldx l0071                                                         ; 2029: a6 71       .q
    bmi return_1                                                      ; 202b: 30 01       0.  ; ALWAYS branch

    nop                                                               ; 202d: ea          .
; $202e referenced 1 time by $202b
return_1
    rts                                                               ; 202e: 60          `

; $202f referenced 1 time by $2003
sub_c202f
    ldy #$ff                                                          ; 202f: a0 ff       ..
    sty l0073                                                         ; 2031: 84 73       .s
    inc l0073                                                         ; 2033: e6 73       .s
    beq c2038                                                         ; 2035: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 2037: ea          .
; $2038 referenced 1 time by $2035
c2038
    lda #$41 ; 'A'                                                    ; 2038: a9 41       .A
    sta l0074                                                         ; 203a: 85 74       .t
    dec l0074                                                         ; 203c: c6 74       .t
    asl l0074                                                         ; 203e: 06 74       .t
    bmi return_2                                                      ; 2040: 30 01       0.  ; ALWAYS branch

    nop                                                               ; 2042: ea          .
; $2043 referenced 1 time by $2040
return_2
    rts                                                               ; 2043: 60          `

; $2044 referenced 1 time by $2006
sub_c2044
    ldx #2                                                            ; 2044: a2 02       ..
    lda #5                                                            ; 2046: a9 05       ..
    sta l0090,x                                                       ; 2048: 95 90       ..
    lda #0                                                            ; 204a: a9 00       ..  ; Redundant instruction?
    lda l0092                                                         ; 204c: a5 92       ..
    cmp #5                                                            ; 204e: c9 05       ..
    beq c2053                                                         ; 2050: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 2052: ea          .
; $2053 referenced 1 time by $2050
c2053
    ldx l0070                                                         ; 2053: a6 70       .p
    lda #0                                                            ; 2055: a9 00       ..
    sta l0090,x                                                       ; 2057: 95 90       ..
    lda l0092                                                         ; 2059: a5 92       ..
    cmp #5                                                            ; 205b: c9 05       ..
    beq return_3                                                      ; 205d: f0 01       ..
    nop                                                               ; 205f: ea          .
; $2060 referenced 1 time by $205d
return_3
    rts                                                               ; 2060: 60          `

; $2061 referenced 1 time by $2009
sub_c2061
    lda #$0f                                                          ; 2061: a9 0f       ..
    sta l0075                                                         ; 2063: 85 75       .u
    lda #0                                                            ; 2065: a9 00       ..
    sta l0080                                                         ; 2067: 85 80       ..
    lda l0070                                                         ; 2069: a5 70       .p
    and l0075                                                         ; 206b: 25 75       %u
    tax                                                               ; 206d: aa          .
    lda l2074,x                                                       ; 206e: bd 74 20    .t
    sta l0081                                                         ; 2071: 85 81       ..
    rts                                                               ; 2073: 60          `

; A table of 16 bytes, indexed by X (0 to 15), read at $206e
; $2074 referenced 1 time by $206e
l2074
    !byte $4f, $4e, $5b, 3, 4, 5, 6, 7, 8, 9, $0a, $0b, $0c, $0d, $0e ; 2074: 4f 4e 5b... ON[
    !byte $0f                                                         ; 2083: 0f          .
    !byte $ff                                                         ; 2084: ff          .

; $2085 referenced 1 time by $200c
sub_c2085
    lda #<l2095                                                       ; 2085: a9 95       ..
    sta l0076                                                         ; 2087: 85 76       .v
    lda #>l2095                                                       ; 2089: a9 20       .
    sta l0077                                                         ; 208b: 85 77       .w
    lda l0070                                                         ; 208d: a5 70       .p
    and #3                                                            ; 208f: 29 03       ).
    tay                                                               ; 2091: a8          .
    lda (l0076),y                                                     ; 2092: b1 76       .v
    rts                                                               ; 2094: 60          `

; A table of 4 bytes, indexed by Y (0 to 3), read at $2092
l2095
    !byte $10, $20, $40, $80                                          ; 2095: 10 20 40... . @
    !text "XYZ"                                                       ; 2099: 58 59 5a    XYZ

; $209c referenced 1 time by $200f
sub_c209c
    lda #<buffer                                                      ; 209c: a9 00       ..
    sta l0078                                                         ; 209e: 85 78       .x
    lda #>buffer                                                      ; 20a0: a9 04       ..
    sta l0079                                                         ; 20a2: 85 79       .y
    lda #0                                                            ; 20a4: a9 00       ..
    tay                                                               ; 20a6: a8          .   ; Y=0
    ; Clear 256 bytes of memory from buffer onwards
; $20a7 referenced 1 time by $20aa
loop_c20a7
    sta (l0078),y                                                     ; 20a7: 91 78       .x  ; A=0
    iny                                                               ; 20a9: c8          .
    bne loop_c20a7                                                    ; 20aa: d0 fb       ..
    rts                                                               ; 20ac: 60          `

; $20ad referenced 1 time by $2012
sub_c20ad
    lda #$e0                                                          ; 20ad: a9 e0       ..
    sta l007a                                                         ; 20af: 85 7a       .z
; $20b1 referenced 1 time by $20b3
loop_c20b1
    lda l007a                                                         ; 20b1: a5 7a       .z
    bmi loop_c20b1                                                    ; 20b3: 30 fc       0.
    rts                                                               ; 20b5: 60          `

; $20b6 referenced 1 time by $2015
sub_c20b6
    lda #3                                                            ; 20b6: a9 03       ..
    sta l007b                                                         ; 20b8: 85 7b       .{
    jsr sub_c20cf                                                     ; 20ba: 20 cf 20     .
    lda l007b                                                         ; 20bd: a5 7b       .{
    cmp #3                                                            ; 20bf: c9 03       ..
    beq c20c4                                                         ; 20c1: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 20c3: ea          .
; $20c4 referenced 1 time by $20c1
c20c4
    jsr sub_c20d2                                                     ; 20c4: 20 d2 20     .
    lda l007b                                                         ; 20c7: a5 7b       .{
    cmp #3                                                            ; 20c9: c9 03       ..
    beq return_4                                                      ; 20cb: f0 01       ..
    nop                                                               ; 20cd: ea          .
; $20ce referenced 1 time by $20cb
return_4
    rts                                                               ; 20ce: 60          `

; $20cf referenced 2 times by $20ba, $20e9
sub_c20cf
    lda l0070                                                         ; 20cf: a5 70       .p
    rts                                                               ; 20d1: 60          `

; $20d2 referenced 2 times by $20c4, $20ec
sub_c20d2
    lda l0070                                                         ; 20d2: a5 70       .p
    sta l007b                                                         ; 20d4: 85 7b       .{
    rts                                                               ; 20d6: 60          `

; $20d7 referenced 1 time by $2018
sub_c20d7
    lda #$80                                                          ; 20d7: a9 80       ..
    sta l007e                                                         ; 20d9: 85 7e       .~
    lda l007e                                                         ; 20db: a5 7e       .~
    bmi return_5                                                      ; 20dd: 30 01       0.
    nop                                                               ; 20df: ea          .
; $20e0 referenced 1 time by $20dd
return_5
    rts                                                               ; 20e0: 60          `

; $20e1 referenced 1 time by $201b
sub_c20e1
    lda #<buffer2                                                     ; 20e1: a9 00       ..
    sta l007c                                                         ; 20e3: 85 7c       .|
    lda #>buffer2                                                     ; 20e5: a9 05       ..
    sta l007d                                                         ; 20e7: 85 7d       .}
    jsr sub_c20cf                                                     ; 20e9: 20 cf 20     .
    jsr sub_c20d2                                                     ; 20ec: 20 d2 20     .
    lda #0                                                            ; 20ef: a9 00       ..
    tay                                                               ; 20f1: a8          .   ; Y=0
    ; Clear 256 bytes of memory from buffer2 onwards
; $20f2 referenced 1 time by $20f5
loop_c20f2
    sta (l007c),y                                                     ; 20f2: 91 7c       .|  ; A=0
    iny                                                               ; 20f4: c8          .
    bne loop_c20f2                                                    ; 20f5: d0 fb       ..
    rts                                                               ; 20f7: 60          `

pydis_end

!if (<buffer) != $00 {
    !error "Assertion failed: <buffer == $00"
}
!if (<buffer2) != $00 {
    !error "Assertion failed: <buffer2 == $00"
}
!if (<l2095) != $95 {
    !error "Assertion failed: <l2095 == $95"
}
!if (>buffer) != $04 {
    !error "Assertion failed: >buffer == $04"
}
!if (>buffer2) != $05 {
    !error "Assertion failed: >buffer2 == $05"
}
!if (>l2095) != $20 {
    !error "Assertion failed: >l2095 == $20"
}

; Label references by decreasing frequency:
;     l0070:        6
;     l007b:        4
;     l0074:        3
;     l0071:        2
;     l0073:        2
;     l0075:        2
;     l0076:        2
;     l0078:        2
;     l007a:        2
;     l007c:        2
;     l007e:        2
;     l0090:        2
;     l0092:        2
;     sub_c20cf:    2
;     sub_c20d2:    2
;     c2038:        1
;     c2053:        1
;     c20c4:        1
;     l0072:        1
;     l0077:        1
;     l0079:        1
;     l007d:        1
;     l0080:        1
;     l0081:        1
;     l2074:        1
;     loop_c20a7:   1
;     loop_c20b1:   1
;     loop_c20f2:   1
;     return_1:     1
;     return_2:     1
;     return_3:     1
;     return_4:     1
;     return_5:     1
;     sub_c201f:    1
;     sub_c202f:    1
;     sub_c2044:    1
;     sub_c2061:    1
;     sub_c2085:    1
;     sub_c209c:    1
;     sub_c20ad:    1
;     sub_c20b6:    1
;     sub_c20d7:    1
;     sub_c20e1:    1

; Automatically generated labels:
;     c2038
;     c2053
;     c20c4
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
;     l0080
;     l0081
;     l0090
;     l0092
;     l2074
;     l2095
;     loop_c20a7
;     loop_c20b1
;     loop_c20f2
;     return_1
;     return_2
;     return_3
;     return_4
;     return_5
;     sub_c201f
;     sub_c202f
;     sub_c2044
;     sub_c2061
;     sub_c2085
;     sub_c209c
;     sub_c20ad
;     sub_c20b6
;     sub_c20cf
;     sub_c20d2
;     sub_c20d7
;     sub_c20e1

; Stats:
;
;     Total size (Code + Data) = 248 bytes
;     Code                     = 224 bytes (90%)
;     Data                     = 24 bytes (10%)
;
;     Number of instructions   = 118
;     Number of data bytes     = 21 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

