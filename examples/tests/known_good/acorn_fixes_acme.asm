; Memory locations

; Zero page ($0000-$00ff)
l0070   = $70

; MOS entry points ($ffb3-$fff9)
OSWRCH  = $ffee

    * = $2000

pydis_start
start
    ldx l0070                                                         ; 2000: a6 70       .p
    ; Position text cursor at (X,?)
    lda #$1f                                                          ; 2002: a9 1f       ..
    jsr OSWRCH                                                        ; 2004: 20 ee ff     .. ; Write character 31
    txa                                                               ; 2007: 8a          .
    jsr OSWRCH                                                        ; 2008: 20 ee ff     .. ; Write character
    inx                                                               ; 200b: e8          .
    jsr OSWRCH                                                        ; 200c: 20 ee ff     .. ; Write character
    rts                                                               ; 200f: 60          `

    ; table of offsets for each character row
    !byte   0,   0, $40,   1, $80,   2, $c0,   3,   0,   5, $40,   6  ; 2010: 00 00 40... ..@
    !byte $80,   7, $c0,   8,   0, $0a, $40, $0b, $80, $0c, $c0, $0d  ; 201c: 80 07 c0... ...
    !byte   0, $0f, $40, $10, $80, $11, $c0, $12,   0, $14, $40, $15  ; 2028: 00 0f 40... ..@
    !byte $80, $16, $c0, $17,   0, $19, $40, $1a, $80, $1b, $c0, $1c  ; 2034: 80 16 c0... ...
    !byte   0, $1e, $40, $1f, $80, $20, $c0, $21,   0                 ; 2040: 00 1e 40... ..@
    !text "#@$"                                                       ; 2049: 23 40 24    #@$
    !byte $80, $25, $c0, $26                                          ; 204c: 80 25 c0... .%.
pydis_end


; Label references by decreasing frequency:
;     OSWRCH:   3
;     l0070:    1

; Automatically generated labels:
;     l0070

; Stats:
;
;     Total size (Code + Data) = 80 bytes
;     Code                     = 16 bytes (20%)
;     Data                     = 64 bytes (80%)
;
;     Number of instructions   = 8
;     Number of data bytes     = 61 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

