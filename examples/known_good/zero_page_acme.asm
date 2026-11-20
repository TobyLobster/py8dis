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
l007e   = $7e
l0080   = $80
l0081   = $81
l0090   = $90
l0092   = $92

; Other
buffer  = $0400

    * = $2000

pydis_start
start
    jsr sub_c201c                                                     ; 2000: 20 1c 20     .
    jsr sub_c202c                                                     ; 2003: 20 2c 20     ,
    jsr sub_c2041                                                     ; 2006: 20 41 20     A
    jsr sub_c205e                                                     ; 2009: 20 5e 20     ^
    jsr sub_c2082                                                     ; 200c: 20 82 20     .
    jsr sub_c2099                                                     ; 200f: 20 99 20     .
    jsr sub_c20aa                                                     ; 2012: 20 aa 20     .
    jsr sub_c20b3                                                     ; 2015: 20 b3 20     .
    jsr sub_c20d4                                                     ; 2018: 20 d4 20     .
    rts                                                               ; 201b: 60          `

; $201c referenced 1 time by $2000
sub_c201c
    lda l0070                                                         ; 201c: a5 70       .p
    ora #$80                                                          ; 201e: 09 80       ..
    sta l0071                                                         ; 2020: 85 71       .q
    lda #0                                                            ; 2022: a9 00       ..
    sta l0072                                                         ; 2024: 85 72       .r
    ldx l0071                                                         ; 2026: a6 71       .q
    bmi return_1                                                      ; 2028: 30 01       0.  ; ALWAYS branch

    nop                                                               ; 202a: ea          .
; $202b referenced 1 time by $2028
return_1
    rts                                                               ; 202b: 60          `

; $202c referenced 1 time by $2003
sub_c202c
    ldy #$ff                                                          ; 202c: a0 ff       ..
    sty l0073                                                         ; 202e: 84 73       .s
    inc l0073                                                         ; 2030: e6 73       .s
    beq c2035                                                         ; 2032: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 2034: ea          .
; $2035 referenced 1 time by $2032
c2035
    lda #$41 ; 'A'                                                    ; 2035: a9 41       .A
    sta l0074                                                         ; 2037: 85 74       .t
    dec l0074                                                         ; 2039: c6 74       .t
    asl l0074                                                         ; 203b: 06 74       .t
    bmi return_2                                                      ; 203d: 30 01       0.  ; ALWAYS branch

    nop                                                               ; 203f: ea          .
; $2040 referenced 1 time by $203d
return_2
    rts                                                               ; 2040: 60          `

; $2041 referenced 1 time by $2006
sub_c2041
    ldx #2                                                            ; 2041: a2 02       ..
    lda #5                                                            ; 2043: a9 05       ..
    sta l0090,x                                                       ; 2045: 95 90       ..
    lda #0                                                            ; 2047: a9 00       ..  ; Redundant instruction?
    lda l0092                                                         ; 2049: a5 92       ..
    cmp #5                                                            ; 204b: c9 05       ..
    beq c2050                                                         ; 204d: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 204f: ea          .
; $2050 referenced 1 time by $204d
c2050
    ldx l0070                                                         ; 2050: a6 70       .p
    lda #0                                                            ; 2052: a9 00       ..
    sta l0090,x                                                       ; 2054: 95 90       ..
    lda l0092                                                         ; 2056: a5 92       ..
    cmp #5                                                            ; 2058: c9 05       ..
    beq return_3                                                      ; 205a: f0 01       ..
    nop                                                               ; 205c: ea          .
; $205d referenced 1 time by $205a
return_3
    rts                                                               ; 205d: 60          `

; $205e referenced 1 time by $2009
sub_c205e
    lda #$0f                                                          ; 205e: a9 0f       ..
    sta l0075                                                         ; 2060: 85 75       .u
    lda #0                                                            ; 2062: a9 00       ..
    sta l0080                                                         ; 2064: 85 80       ..
    lda l0070                                                         ; 2066: a5 70       .p
    and l0075                                                         ; 2068: 25 75       %u
    tax                                                               ; 206a: aa          .
    lda l2071,x                                                       ; 206b: bd 71 20    .q
    sta l0081                                                         ; 206e: 85 81       ..
    rts                                                               ; 2070: 60          `

; A table of 16 bytes, indexed by X (0 to 15), read at $206b
; $2071 referenced 1 time by $206b
l2071
    !byte $4f, $4e, $5b, 3, 4, 5, 6, 7, 8, 9, $0a, $0b, $0c, $0d, $0e ; 2071: 4f 4e 5b... ON[
    !byte $0f                                                         ; 2080: 0f          .
    !byte $ff                                                         ; 2081: ff          .

; $2082 referenced 1 time by $200c
sub_c2082
    lda #<l2092                                                       ; 2082: a9 92       ..
    sta l0076                                                         ; 2084: 85 76       .v
    lda #>l2092                                                       ; 2086: a9 20       .
    sta l0077                                                         ; 2088: 85 77       .w
    lda l0070                                                         ; 208a: a5 70       .p
    and #3                                                            ; 208c: 29 03       ).
    tay                                                               ; 208e: a8          .
    lda (l0076),y                                                     ; 208f: b1 76       .v
    rts                                                               ; 2091: 60          `

; A table of 4 bytes, indexed by Y (0 to 3), read at $208f
l2092
    !byte $10, $20, $40, $80                                          ; 2092: 10 20 40... . @
    !text "XYZ"                                                       ; 2096: 58 59 5a    XYZ

; $2099 referenced 1 time by $200f
sub_c2099
    lda #<buffer                                                      ; 2099: a9 00       ..
    sta l0078                                                         ; 209b: 85 78       .x
    lda #>buffer                                                      ; 209d: a9 04       ..
    sta l0079                                                         ; 209f: 85 79       .y
    lda #0                                                            ; 20a1: a9 00       ..
    tay                                                               ; 20a3: a8          .   ; Y=0
    ; Clear 256 bytes of memory from buffer onwards
; $20a4 referenced 1 time by $20a7
loop_c20a4
    sta (l0078),y                                                     ; 20a4: 91 78       .x  ; A=0
    iny                                                               ; 20a6: c8          .
    bne loop_c20a4                                                    ; 20a7: d0 fb       ..
    rts                                                               ; 20a9: 60          `

; $20aa referenced 1 time by $2012
sub_c20aa
    lda #$e0                                                          ; 20aa: a9 e0       ..
    sta l007a                                                         ; 20ac: 85 7a       .z
; $20ae referenced 1 time by $20b0
loop_c20ae
    lda l007a                                                         ; 20ae: a5 7a       .z
    bmi loop_c20ae                                                    ; 20b0: 30 fc       0.
    rts                                                               ; 20b2: 60          `

; $20b3 referenced 1 time by $2015
sub_c20b3
    lda #3                                                            ; 20b3: a9 03       ..
    sta l007b                                                         ; 20b5: 85 7b       .{
    jsr sub_c20cc                                                     ; 20b7: 20 cc 20     .
    lda l007b                                                         ; 20ba: a5 7b       .{
    cmp #3                                                            ; 20bc: c9 03       ..
    beq c20c1                                                         ; 20be: f0 01       ..  ; ALWAYS branch

    nop                                                               ; 20c0: ea          .
; $20c1 referenced 1 time by $20be
c20c1
    jsr sub_c20cf                                                     ; 20c1: 20 cf 20     .
    lda l007b                                                         ; 20c4: a5 7b       .{
    cmp #3                                                            ; 20c6: c9 03       ..
    beq return_4                                                      ; 20c8: f0 01       ..
    nop                                                               ; 20ca: ea          .
; $20cb referenced 1 time by $20c8
return_4
    rts                                                               ; 20cb: 60          `

; $20cc referenced 1 time by $20b7
sub_c20cc
    lda l0070                                                         ; 20cc: a5 70       .p
    rts                                                               ; 20ce: 60          `

; $20cf referenced 1 time by $20c1
sub_c20cf
    lda l0070                                                         ; 20cf: a5 70       .p
    sta l007b                                                         ; 20d1: 85 7b       .{
    rts                                                               ; 20d3: 60          `

; $20d4 referenced 1 time by $2018
sub_c20d4
    lda #$80                                                          ; 20d4: a9 80       ..
    sta l007e                                                         ; 20d6: 85 7e       .~
    lda l007e                                                         ; 20d8: a5 7e       .~
    bmi return_5                                                      ; 20da: 30 01       0.
    nop                                                               ; 20dc: ea          .
; $20dd referenced 1 time by $20da
return_5
    rts                                                               ; 20dd: 60          `

pydis_end

!if (<buffer) != $00 {
    !error "Assertion failed: <buffer == $00"
}
!if (<l2092) != $92 {
    !error "Assertion failed: <l2092 == $92"
}
!if (>buffer) != $04 {
    !error "Assertion failed: >buffer == $04"
}
!if (>l2092) != $20 {
    !error "Assertion failed: >l2092 == $20"
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
;     l007e:        2
;     l0090:        2
;     l0092:        2
;     c2035:        1
;     c2050:        1
;     c20c1:        1
;     l0072:        1
;     l0077:        1
;     l0079:        1
;     l0080:        1
;     l0081:        1
;     l2071:        1
;     loop_c20a4:   1
;     loop_c20ae:   1
;     return_1:     1
;     return_2:     1
;     return_3:     1
;     return_4:     1
;     return_5:     1
;     sub_c201c:    1
;     sub_c202c:    1
;     sub_c2041:    1
;     sub_c205e:    1
;     sub_c2082:    1
;     sub_c2099:    1
;     sub_c20aa:    1
;     sub_c20b3:    1
;     sub_c20cc:    1
;     sub_c20cf:    1
;     sub_c20d4:    1

; Automatically generated labels:
;     c2035
;     c2050
;     c20c1
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
;     l007e
;     l0080
;     l0081
;     l0090
;     l0092
;     l2071
;     l2092
;     loop_c20a4
;     loop_c20ae
;     return_1
;     return_2
;     return_3
;     return_4
;     return_5
;     sub_c201c
;     sub_c202c
;     sub_c2041
;     sub_c205e
;     sub_c2082
;     sub_c2099
;     sub_c20aa
;     sub_c20b3
;     sub_c20cc
;     sub_c20cf
;     sub_c20d4

; Stats:
;
;     Total size (Code + Data) = 222 bytes
;     Code                     = 198 bytes (89%)
;     Data                     = 24 bytes (11%)
;
;     Number of instructions   = 105
;     Number of data bytes     = 21 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

