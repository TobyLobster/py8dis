; Constants
low_seven_bits  = 127

; Memory locations

; Other
l0000   = &0000

; Workspace (&0070-&0072)
l0070   = &0070
value   = &0070
temp    = &0071
temp_2  = &0072

    org &2000

.pydis_start
.start
    ldy #3                                                            ; 2000: a0 03       ..
    lda #7                                                            ; 2002: a9 07       .. ; A=value to store
    jsr store_value                                                   ; 2004: 20 2f 20     / ; Store a value
    stx temp                                                          ; 2007: 86 71       .q
    sty temp_2                                                        ; 2009: 84 72       .r ; Y=count
    jsr quiet_routine                                                 ; 200b: 20 36 20     6 ; Calls quiet_routine ; quiet_routine is quiet
    lda #5                                                            ; 200e: a9 05       ..
    sec                                                               ; 2010: 38          8
    and (l0070,x)                                                     ; 2011: 21 70       !p
    tay                                                               ; 2013: a8          .
    adc #1                                                            ; 2014: 69 01       i. ; Carry is set, so adding 2
    lda value                                                         ; 2016: a5 70       .p
    ldx #0                                                            ; 2018: a2 00       ..
    and #&ff                                                          ; 201a: 29 ff       ).
    beq c202c                                                         ; 201c: f0 0e       ..
    lda value                                                         ; 201e: a5 70       .p
    ldx #NOT(low_seven_bits) AND &ff                                  ; 2020: a2 80       ..
    ora #1                                                            ; 2022: 09 01       ..
    bmi c202c                                                         ; 2024: 30 06       0.
    lda #5                                                            ; 2026: a9 05       ..
    cmp #7                                                            ; 2028: c9 07       ..
    ror a                                                             ; 202a: 6a          j
    tax                                                               ; 202b: aa          .
; &202c referenced 2 times by &201c, &2024
.c202c
    jmp part2                                                         ; 202c: 4c 80 20    L.

; ***************************************************************************************
; Store a value
; 
; On Entry:
;     A: value to store
;     Y: (ignored)
; 
; On Exit:
;     A: (corrupted)
;     Y: count
; ***************************************************************************************
; &202f referenced 2 times by &2004, &2080
.store_value
    sta l0070                                                         ; 202f: 85 70       .p
    ldx #0                                                            ; 2031: a2 00       ..
    ldy #1                                                            ; 2033: a0 01       ..
    rts                                                               ; 2035: 60          `

; ***************************************************************************************
; Quiet routine
; ***************************************************************************************
; &2036 referenced 1 time by &200b
.quiet_routine
    rts                                                               ; 2036: 60          `

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2037: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2043: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 204f: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 205b: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2067: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2073: ea ea ea... ...
    equb &ea                                                          ; 207f: ea          .

.part2
    jsr store_value                                                   ; 2080: 20 2f 20     /
    rts                                                               ; 2083: 60          `

    equb l2085 - l2085                                                ; 2084: 00          .
.l2085
    equw (l0000 - 1) AND &ffff                                        ; 2085: ff ff       ..
    equb >(l0000 - 1)                                                 ; 2087: ff          .
    equb <(l0000 - 1)                                                 ; 2088: ff          .
    equs "END"                                                        ; 2089: 45 4e 44    END
.pydis_end

    assert &ffff == ((l0000 - 1) AND &ffff)
    assert &ff == <(l0000 - 1)
    assert &ff == >(l0000 - 1)
    assert &80 == (NOT(low_seven_bits) AND &ff)
    assert &00 == l2085 - l2085

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l0070:           4
;     value:           4
;     c202c:           2
;     store_value:     2
;     part2:           1
;     quiet_routine:   1
;     temp:            1
;     temp_2:          1

; Automatically generated labels:
;     c202c
;     l0000
;     l0070
;     l2085

; Stats:
;
;     Total size (Code + Data) = 140 bytes
;     Code                     = 59 bytes (42%)
;     Data                     = 81 bytes (58%)
;
;     Number of instructions   = 31
;     Number of data bytes     = 76 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

