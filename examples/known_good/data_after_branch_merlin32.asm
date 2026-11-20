; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0070   equ $70
l0071   equ $71
l0072   equ $72

    org $2000

pydis_start
start
    jsr sub_c200a                                                     ; 2000: 20 0a 20     .
    jsr sub_c201e                                                     ; 2003: 20 1e 20     .
    jsr sub_c2032                                                     ; 2006: 20 32 20     2
    rts                                                               ; 2009: 60          `

; $200a referenced 1 time by $2000
sub_c200a
    ldy l0070                                                         ; 200a: a4 70       .p
    cpy #4                                                            ; 200c: c0 04       ..
    bcs c2015                                                         ; 200e: b0 05       ..
    lda l2019,y                                                       ; 2010: b9 19 20    ..
    sta l0071                                                         ; 2013: 85 71       .q
; $2015 referenced 1 time by $200e
c2015
    ldx #0                                                            ; 2015: a2 00       ..
    beq return_1                                                      ; 2017: f0 04       ..  ; ALWAYS branch

; A table of 4 bytes, indexed by Y (0 to 3), read at $2010
; $2019 referenced 1 time by $2010
l2019
    dfb $a1, 0, $22, $11                                              ; 2019: a1 00 22... .."

; $201d referenced 1 time by $2017
return_1
    rts                                                               ; 201d: 60          `

; $201e referenced 1 time by $2003
sub_c201e
    ldy l0070                                                         ; 201e: a4 70       .p
    cpy #4                                                            ; 2020: c0 04       ..
    bcs c2029                                                         ; 2022: b0 05       ..
    lda c202d,y                                                       ; 2024: b9 2d 20    .-
    sta l0071                                                         ; 2027: 85 71       .q
; $2029 referenced 1 time by $2022
c2029
    ldx #0                                                            ; 2029: a2 00       ..
    beq return_2                                                      ; 202b: f0 04       ..  ; ALWAYS branch

; $202d referenced 1 time by $2024
c202d
    lda #0                                                            ; 202d: a9 00       ..
    rts                                                               ; 202f: 60          `

    dfb $ea                                                           ; 2030: ea          .

; $2031 referenced 1 time by $202b
return_2
    rts                                                               ; 2031: 60          `

; $2032 referenced 1 time by $2006
sub_c2032
    lda l0072                                                         ; 2032: a5 72       .r
    bne c2045                                                         ; 2034: d0 0f       ..
    ldy l0070                                                         ; 2036: a4 70       .p
    cpy #4                                                            ; 2038: c0 04       ..
    bcs c2041                                                         ; 203a: b0 05       ..
    lda c2045,y                                                       ; 203c: b9 45 20    .E
    sta l0071                                                         ; 203f: 85 71       .q
; $2041 referenced 1 time by $203a
c2041
    ldx #0                                                            ; 2041: a2 00       ..
    beq return_3                                                      ; 2043: f0 04       ..  ; ALWAYS branch

; $2045 referenced 2 times by $2034, $203c
c2045
    nop                                                               ; 2045: ea          .
    dfb 2, $33, $44                                                   ; 2046: 02 33 44    .3D

; $2049 referenced 1 time by $2043
return_3
    rts                                                               ; 2049: 60          `

pydis_end


; Label references by decreasing frequency:
;     l0070:       3
;     l0071:       3
;     c2045:       2
;     c2015:       1
;     c2029:       1
;     c202d:       1
;     c2041:       1
;     l0072:       1
;     l2019:       1
;     return_1:    1
;     return_2:    1
;     return_3:    1
;     sub_c200a:   1
;     sub_c201e:   1
;     sub_c2032:   1

; Automatically generated labels:
;     c2015
;     c2029
;     c202d
;     c2041
;     c2045
;     l0070
;     l0071
;     l0072
;     l2019
;     return_1
;     return_2
;     return_3
;     sub_c200a
;     sub_c201e
;     sub_c2032

; Stats:
;
;     Total size (Code + Data) = 74 bytes
;     Code                     = 66 bytes (89%)
;     Data                     = 8 bytes (11%)
;
;     Number of instructions   = 33
;     Number of data bytes     = 8 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
