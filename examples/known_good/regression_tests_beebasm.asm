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

; Other
l0073   = &0073
l03a0   = &03a0

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
;     A: (preserved)
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

    ; Found by a snippet with a wildcard
    ldy #3                                                            ; 2037: a0 03       ..
    cpx #4                                                            ; 2039: e0 04       ..
    sta l0073                                                         ; 203b: 85 73       .s
    rts                                                               ; 203d: 60          `

.mid_instruction_snippet
    bit l03a0                                                         ; 203e: 2c a0 03    ,..
    cpx #4                                                            ; 2041: e0 04       ..
    sta l0073                                                         ; 2043: 85 73       .s
    rts                                                               ; 2045: 60          `

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2046: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 2052: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 205e: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea   ; 206a: ea ea ea... ...
    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea             ; 2076: ea ea ea... ...

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
;     l0073:           2
;     store_value:     2
;     l03a0:           1
;     part2:           1
;     quiet_routine:   1
;     temp:            1
;     temp_2:          1

; Automatically generated labels:
;     c202c
;     l0000
;     l0070
;     l0073
;     l03a0
;     l2085

; Stats:
;
;     Total size (Code + Data) = 140 bytes
;     Code                     = 74 bytes (53%)
;     Data                     = 66 bytes (47%)
;
;     Number of instructions   = 39
;     Number of data bytes     = 61 bytes
;     Number of data words     = 2 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

