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

; Other
l04a9   = $04a9
lfe40   = $fe40

    * = $2000

pydis_start
start
    lda #3                                                            ; 2000: a9 03       ..
c2002
middle = c2002+1
    bit l04a9                                                         ; 2002: 2c a9 04    ,..
; overlapping: lda #4                                                 ; 2003: a9 04       ..
; $2003 referenced 1 time by $2034
    ldx #5                                                            ; 2005: a2 05       .. ; Redundant instruction?
    tax                                                               ; 2007: aa          .
    clc                                                               ; 2008: 18          .
    adc #1                                                            ; 2009: 69 01       i.
    sta l0078                                                         ; 200b: 85 78       .x
    lda l0070                                                         ; 200d: a5 70       .p ; Redundant instruction?
    pla                                                               ; 200f: 68          h
    lda l0071                                                         ; 2010: a5 71       .q ; Redundant instruction?
    and #3                                                            ; 2012: 29 03       ). ; Redundant instruction?
    lda l0072                                                         ; 2014: a5 72       .r
    sec                                                               ; 2016: 38          8  ; Redundant instruction?
    sec                                                               ; 2017: 38          8  ; Redundant instruction?
    cpx l0073                                                         ; 2018: e4 73       .s ; Redundant instruction?
    cpx l0073                                                         ; 201a: e4 73       .s
    bne return_1                                                      ; 201c: d0 18       ..
    lda l0074                                                         ; 201e: a5 74       .t
    sta l0075                                                         ; 2020: 85 75       .u
    lda l0076                                                         ; 2022: a5 76       .v ; Redundant instruction?
    ldx lfe40                                                         ; 2024: ae 40 fe    .@.
    ldx #0                                                            ; 2027: a2 00       ..
    lda (l0077),y                                                     ; 2029: b1 77       .w
    lda #1                                                            ; 202b: a9 01       ..
    ldy #1                                                            ; 202d: a0 01       ..
    jsr return_1                                                      ; 202f: 20 36 20     6
    ldy #2                                                            ; 2032: a0 02       ..
    beq middle                                                        ; 2034: f0 cd       ..
; $2036 referenced 2 times by $201c, $202f
return_1
    rts                                                               ; 2036: 60          `

pydis_end


; Label references by decreasing frequency:
;     l0073:      2
;     return_1:   2
;     l0070:      1
;     l0071:      1
;     l0072:      1
;     l0074:      1
;     l0075:      1
;     l0076:      1
;     l0077:      1
;     l0078:      1
;     l04a9:      1
;     lfe40:      1
;     middle:     1

; Automatically generated labels:
;     c2002
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0075
;     l0076
;     l0077
;     l0078
;     l04a9
;     lfe40
;     return_1

; Stats:
;
;     Total size (Code + Data) = 55 bytes
;     Code                     = 55 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 29
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

