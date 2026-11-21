; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070

    * = $ffe0

; $ffe0 referenced 1 time by $0900[1]
pydis_start
    lda #1                                                            ; ffe0: a9 01       ..
    sta l0070                                                         ; ffe2: 85 70       .p
    rts                                                               ; ffe4: 60          `

    .byte $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea       ; ffe5: ea ea ea... ...

; Move 1: $fff0 to $0900 for length 16
.logical $0900
start
    jsr pydis_start                                                   ; fff0: 20 e0 ff     .. :0900[1]
    lda l0070                                                         ; fff3: a5 70       .p  :0903[1]
    rts                                                               ; fff5: 60          `   :0905[1]

    .byte $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea, $ea            ; fff6: ea ea ea... ... :0906[1]
.here

pydis_end


; Label references by decreasing frequency:
;     l0070:         2
;     pydis_start:   1

; Automatically generated labels:
;     l0070

; Stats:
;
;     Total size (Code + Data) = 32 bytes
;     Code                     = 11 bytes (34%)
;     Data                     = 21 bytes (66%)
;
;     Number of instructions   = 6
;     Number of data bytes     = 21 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

