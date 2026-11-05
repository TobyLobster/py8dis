; Constants
five    = 5
three   = 3

; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070

; Other
before_banks = $7fff

    * = $2000

pydis_start
start
    .byte $a9                                                         ; 2000: a9          .
    .byte 1                                                           ; 2001: 01          .

    jsr sub_c200e                                                     ; 2002: 20 0e 20     .
    sta l0070                                                         ; 2005: 85 70       .p
    lda before_banks+1                                                ; 2007: ad 00 80    ...            ; Redundant instruction?
    lda l2011                                                         ; 200a: ad 11 20    ..
    rts                                                               ; 200d: 60          `

; $200e referenced 1 time by $2002
sub_c200e
    lda #three                                                        ; 200e: a9 03       ..
    rts                                                               ; 2010: 60          `

; $2011 referenced 1 time by $200a
l2011
    .byte $34                                                         ; 2011: 34          4
    .byte $12, $78, $56                                               ; 2012: 12 78 56    .xV

; Move 1: $2015 to $8000 for length 4
.logical $8000
    .byte 1, 2, 3, 4                                                  ; 2015: 01 02 03... ... :8000[1]
.here


; Move 2: $2019 to $8000 for length 4
.logical $8000
    .byte 5, 6, 7, 8                                                  ; 2019: 05 06 07... ... :8000[2]
.here

    .text "G", $80 + 'O'                                              ; 201d: 47 cf       G.
    .byte >start, <start                                              ; 201f: 20 00        .
pydis_end

.cerror ($80 + 'O') != $cf, "Assertion failed: $80 + 'O' == $cf"
.cerror (<start) != $00, "Assertion failed: <start == $00"
.cerror (>start) != $20, "Assertion failed: >start == $20"

; Label references by decreasing frequency:
;     before_banks+1:   1
;     l0070:            1
;     l2011:            1
;     sub_c200e:        1

; Automatically generated labels:
;     l0070
;     l2011
;     sub_c200e

; Stats:
;
;     Total size (Code + Data) = 33 bytes
;     Code                     = 15 bytes (45%)
;     Data                     = 18 bytes (55%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 16 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 2 bytes
;     Number of strings        = 1

