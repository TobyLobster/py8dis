; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Constants
osbyte_inkey    = 129

; Memory locations

; MOS entry points ($ffb3-$fff9)
gsinit  = $ffc2
gsread  = $ffc5
osasci  = $ffe3
oswrch  = $ffee
osbyte  = $fff4
oscli   = $fff7

    .org $2000

pydis_start:
start:
    lda #$41 ; 'A'                                                    ; 2000: a9 41       .A
    jsr oswrch                                                        ; 2002: 20 ee ff     .. ; Write character 65
    ; Start a new line
    lda #$0d                                                          ; 2005: a9 0d       ..
    jsr osasci                                                        ; 2007: 20 e3 ff     .. ; Write newline (characters 10 and 13)
    lda #osbyte_inkey                                                 ; 200a: a9 81       ..
    ldx #0                                                            ; 200c: a2 00       ..
    ldy #$ff                                                          ; 200e: a0 ff       ..
    jsr osbyte                                                        ; 2010: 20 f4 ff     .. ; Read the machine type
    ldx #<l2022                                                       ; 2013: a2 22       ."
    ldy #>l2022                                                       ; 2015: a0 20       .
    jsr oscli                                                         ; 2017: 20 f7 ff     ..
    clc                                                               ; 201a: 18          .
    jsr gsinit                                                        ; 201b: 20 c2 ff     ..
    jsr gsread                                                        ; 201e: 20 c5 ff     ..
    rts                                                               ; 2021: 60          `

l2022:
    .byte "CAT"                                                       ; 2022: 43 41 54    CAT
    .byte $0d                                                         ; 2025: 0d          .
pydis_end:

.assert (<l2022) = $22, error, "Assertion failed: <l2022 = $22"
.assert (>l2022) = $20, error, "Assertion failed: >l2022 = $20"

; Label references by decreasing frequency:
;     gsinit:   1
;     gsread:   1
;     osasci:   1
;     osbyte:   1
;     oscli:    1
;     oswrch:   1

; Automatically generated labels:
;     l2022

; Stats:
;
;     Total size (Code + Data) = 38 bytes
;     Code                     = 34 bytes (89%)
;     Data                     = 4 bytes (11%)
;
;     Number of instructions   = 15
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 3 bytes
;     Number of strings        = 1

