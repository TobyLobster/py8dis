; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l0070   equ $70

; Other
lffee   equ $ffee

    org $1000

pydis_start
main
    lda #0                                                            ; 1000: a9 00       ..
    sta l0070                                                         ; 1002: 85 70       .p
    jsr bank_a                                                        ; 1004: 20 00 80     ..
    lda #1                                                            ; 1007: a9 01       ..
    sta l0070                                                         ; 1009: 85 70       .p
    jsr bank_b                                                        ; 100b: 20 00 80     ..
    rts                                                               ; 100e: 60          `

    dfb 0                                                             ; 100f: 00          .

    ds $2000-*
    org $2000


; Move 1: $2000 to $8000 for length 26
    org $8000
; $2000 referenced 2 times by $1004, $100b
bank_a
    jsr sub_c8004                                                     ; 2000: 20 04 80     .. :8000[1]
    rts                                                               ; 2003: 60          `   :8003[1]

; $2004 referenced 1 time by $8000[1]
sub_c8004
    ldx #0                                                            ; 2004: a2 00       ..  :8004[1]
; $2006 referenced 1 time by $800f[1]
loop_c8006
    lda l8012,x                                                       ; 2006: bd 12 80    ... :8006[1]
    beq return_1                                                      ; 2009: f0 06       ..  :8009[1]
    jsr lffee                                                         ; 200b: 20 ee ff     .. :800b[1]
    inx                                                               ; 200e: e8          .   :800e[1]
    bne loop_c8006                                                    ; 200f: d0 f5       ..  :800f[1]
; $2011 referenced 1 time by $8009[1]
return_1
    rts                                                               ; 2011: 60          `   :8011[1]

; $2012 referenced 1 time by $8006[1]
l8012
    asc 'Bank A'                                                      ; 2012: 42 61 6e... Ban :8012[1]
    dfb $0d, 0                                                        ; 2018: 0d 00       ..  :8018[1]
    org $201a


    ds $3000-*
    org $3000


; Move 2: $3000 to $8000 for length 25
    org $8000
bank_b
    jmp c800b                                                         ; 3000: 4c 0b 80    L.. :8000[2]

; $3003 referenced 1 time by $800d[2]
l8003
    dfb $42                                                           ; 3003: 42          B   :8003[2]
    dfb $61, $6e                                                      ; 3004: 61 6e       an  :8004[2]
    asc 'k B'                                                         ; 3006: 6b 20 42    k B :8006[2]
    dfb $0d, 0                                                        ; 3009: 0d 00       ..  :8009[2]

; $300b referenced 1 time by $8000[2]
c800b
    ldx #0                                                            ; 300b: a2 00       ..  :800b[2]
; $300d referenced 1 time by $8016[2]
loop_c800d
    lda l8003,x                                                       ; 300d: bd 03 80    ... :800d[2]
    beq return_2                                                      ; 3010: f0 06       ..  :8010[2]
    jsr lffee                                                         ; 3012: 20 ee ff     .. :8012[2]
    inx                                                               ; 3015: e8          .   :8015[2]
    bne loop_c800d                                                    ; 3016: d0 f5       ..  :8016[2]
; $3018 referenced 1 time by $8010[2]
return_2
    rts                                                               ; 3018: 60          `   :8018[2]

    org $3019

pydis_end

    err bank_b - $8000

; Label references by decreasing frequency:
;     bank_a:       2
;     bank_b:       2
;     l0070:        2
;     lffee:        2
;     c800b:        1
;     l8003:        1
;     l8012:        1
;     loop_c8006:   1
;     loop_c800d:   1
;     return_1:     1
;     return_2:     1
;     sub_c8004:    1

; Automatically generated labels:
;     c800b
;     l0070
;     l8003
;     l8012
;     lffee
;     loop_c8006
;     loop_c800d
;     return_1
;     return_2
;     sub_c8004

; Stats:
;
;     Total size (Code + Data) = 67 bytes
;     Code                     = 50 bytes (75%)
;     Data                     = 17 bytes (25%)
;
;     Number of instructions   = 24
;     Number of data bytes     = 8 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 9 bytes
;     Number of strings        = 2
