; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Constants
osbyte_inkey    equ 129

; Memory locations

; MOS entry points ($ffb3-$fff9)
gsinit  equ $ffc2
gsread  equ $ffc5
osasci  equ $ffe3
oswrch  equ $ffee
osbyte  equ $fff4
oscli   equ $fff7

    org $2000

pydis_start
start
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

l2022
    asc 'CAT'                                                         ; 2022: 43 41 54    CAT
    dfb $0d                                                           ; 2025: 0d          .
pydis_end

    err l2022 & $ff - $22
    err l2022 & $ffff / $0100 - $20

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
