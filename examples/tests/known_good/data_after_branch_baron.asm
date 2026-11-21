; Assemble with Baron, which writes the program to the file named in its
; section (data_after_branch_baron), in the folder given with -p:
;     baron -p . data_after_branch_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070
l0071   = &0071
l0072   = &0072
l0086   = &0086

; Other
l3000   = &3000

section pydis, org = &2000, filename = "data_after_branch_baron"

.pydis_start
.start
    jsr sub_c2010                                                     ; 2000: 20 10 20     .
    jsr sub_c2024                                                     ; 2003: 20 24 20     $
    jsr sub_c2038                                                     ; 2006: 20 38 20     8
    jsr sub_c2050                                                     ; 2009: 20 50 20     P
    jsr sub_c205b                                                     ; 200c: 20 5b 20     [
    rts                                                               ; 200f: 60          `

; &2010 referenced 1 time by &2000
.sub_c2010
    ldy l0070                                                         ; 2010: a4 70       .p
    cpy #4                                                            ; 2012: c0 04       ..
    bcs c201b                                                         ; 2014: b0 05       ..
    lda l201f,y                                                       ; 2016: b9 1f 20    ..
    sta l0071                                                         ; 2019: 85 71       .q
; &201b referenced 1 time by &2014
.c201b
    ldx #0                                                            ; 201b: a2 00       ..
    beq return_1                                                      ; 201d: f0 04       ..  ; ALWAYS branch

; A table of 4 bytes, indexed by Y (0 to 3), read at &2016
; &201f referenced 1 time by &2016
.l201f
    equb &a1, 0, &22, &11                                             ; 201f: a1 00 22... .."

; &2023 referenced 1 time by &201d
.return_1
    rts                                                               ; 2023: 60          `

; &2024 referenced 1 time by &2003
.sub_c2024
    ldy l0070                                                         ; 2024: a4 70       .p
    cpy #4                                                            ; 2026: c0 04       ..
    bcs c202f                                                         ; 2028: b0 05       ..
    lda c2033,y                                                       ; 202a: b9 33 20    .3
    sta l0071                                                         ; 202d: 85 71       .q
; &202f referenced 1 time by &2028
.c202f
    ldx #0                                                            ; 202f: a2 00       ..
    beq return_2                                                      ; 2031: f0 04       ..  ; ALWAYS branch

; &2033 referenced 1 time by &202a
.c2033
    lda #0                                                            ; 2033: a9 00       ..
    rts                                                               ; 2035: 60          `

    equb &ea                                                          ; 2036: ea          .

; &2037 referenced 1 time by &2031
.return_2
    rts                                                               ; 2037: 60          `

; &2038 referenced 1 time by &2006
.sub_c2038
    lda l0072                                                         ; 2038: a5 72       .r
    bne c204b                                                         ; 203a: d0 0f       ..
    ldy l0070                                                         ; 203c: a4 70       .p
    cpy #4                                                            ; 203e: c0 04       ..
    bcs c2047                                                         ; 2040: b0 05       ..
    lda c204b,y                                                       ; 2042: b9 4b 20    .K
    sta l0071                                                         ; 2045: 85 71       .q
; &2047 referenced 1 time by &2040
.c2047
    ldx #0                                                            ; 2047: a2 00       ..
    beq return_3                                                      ; 2049: f0 04       ..  ; ALWAYS branch

; &204b referenced 2 times by &203a, &2042
.c204b
    nop                                                               ; 204b: ea          .
    equb 2, &33, &44                                                  ; 204c: 02 33 44    .3D

; &204f referenced 1 time by &2049
.return_3
    rts                                                               ; 204f: 60          `

; &2050 referenced 1 time by &2009
.sub_c2050
    ldx #0                                                            ; 2050: a2 00       ..
    beq return_4                                                      ; 2052: f0 06       ..  ; ALWAYS branch

.table4
    equb &84, &86, &8c, &98, &e2, 2                                   ; 2054: 84 86 8c... ...

; &205a referenced 1 time by &2052
.return_4
    rts                                                               ; 205a: 60          `

; &205b referenced 1 time by &200c
.sub_c205b
    ldx #0                                                            ; 205b: a2 00       ..
    beq return_5                                                      ; 205d: f0 06       ..  ; ALWAYS branch

; overlapping: sty l0086                                              ; 205f: 84 86       ..
.table5
    equb &84, &86, &20, 0, &30, 2                                     ; 205f: 84 86 20... ..
; overlapping: jsr l3000                                              ; 2061: 20 00 30     .0

; &2065 referenced 1 time by &205d
.return_5
    rts                                                               ; 2065: 60          `

.pydis_end


endsection

; Label references by decreasing frequency:
;     l0070:       3
;     l0071:       3
;     c204b:       2
;     c201b:       1
;     c202f:       1
;     c2033:       1
;     c2047:       1
;     l0072:       1
;     l201f:       1
;     return_1:    1
;     return_2:    1
;     return_3:    1
;     return_4:    1
;     return_5:    1
;     sub_c2010:   1
;     sub_c2024:   1
;     sub_c2038:   1
;     sub_c2050:   1
;     sub_c205b:   1

; Automatically generated labels:
;     c201b
;     c202f
;     c2033
;     c2047
;     c204b
;     l0070
;     l0071
;     l0072
;     l0086
;     l201f
;     l3000
;     return_1
;     return_2
;     return_3
;     return_4
;     return_5
;     sub_c2010
;     sub_c2024
;     sub_c2038
;     sub_c2050
;     sub_c205b

; Stats:
;
;     Total size (Code + Data) = 102 bytes
;     Code                     = 82 bytes (80%)
;     Data                     = 20 bytes (20%)
;
;     Number of instructions   = 41
;     Number of data bytes     = 20 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
