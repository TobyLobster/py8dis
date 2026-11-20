; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071
l0072   = $0072
l0073   = $0073
l0074   = $0074

; OS vectors ($0200-$0235)
ind1v   = $0230

; User memory ($0e00-$7fff)
external_routine = $3000

; MOS entry points ($ffb3-$fff9)
OSRDCH  = $ffe0
OSWRCH  = $ffee

    .org $2000

pydis_start:
start:
    ; print message
    ldy #0                                                            ; 2000: a0 00       ..  A:-- X:-- Y:00 n---Z-
; $2002 referenced 1 time by $200b
loop_c2002:
    lda l2039,y                                                       ; 2002: b9 39 20    .9  A:-- X:-- Y:0- ------
    jsr OSWRCH                                                        ; 2005: 20 ee ff     .. A:-- X:-- Y:0- --d--- ; Write character
    iny                                                               ; 2008: c8          .   A:-- X:-- Y:0- n-d-z-
    cpy #5                                                            ; 2009: c0 05       ..  A:-- X:-- Y:0- --d-??
    bne loop_c2002                                                    ; 200b: d0 f5       ..  A:-- X:-- Y:05 n-d-ZC
    sty l0070                                                         ; 200d: 84 70       .p  A:-- X:-- Y:05 n-d-ZC ; Y=5
    ; Print "AA"
    lda #$41 ; 'A'                                                    ; 200f: a9 41       .A  A:41 X:-- Y:05 n-d-zC
    jsr OSWRCH                                                        ; 2011: 20 ee ff     .. A:41 X:-- Y:05 --d--- ; Write character 65
    jsr OSWRCH                                                        ; 2014: 20 ee ff     .. A:41 X:-- Y:05 --d--- ; Write character 65
    lda #1                                                            ; 2017: a9 01       ..  A:01 X:-- Y:05 n-d-z-
    clc                                                               ; 2019: 18          .   A:01 X:-- Y:05 n-d-zc
    adc #2                                                            ; 201a: 69 02       i.  A:03 X:-- Y:05 nvd-zc ; A=3
    sta l0071                                                         ; 201c: 85 71       .q  A:03 X:-- Y:05 nvd-zc
    ldx #3                                                            ; 201e: a2 03       ..  A:03 X:03 Y:05 nvd-zc
    jsr OSRDCH                                                        ; 2020: 20 e0 ff     .. A:-- X:03 Y:05 --d--- ; Read a character from the current input stream
    stx l0072                                                         ; 2023: 86 72       .r  A:-- X:03 Y:05 --d---
    ldx #7                                                            ; 2025: a2 07       ..  A:-- X:07 Y:05 n-d-z-
    jsr external_routine                                              ; 2027: 20 00 30     .0 A:-- X:07 Y:-- -----c
    stx l0073                                                         ; 202a: 86 73       .s  A:-- X:07 Y:-- -----c
    bcc c202e                                                         ; 202c: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $202e referenced 1 time by $202c
c202e:
    ldy #9                                                            ; 202e: a0 09       ..  A:-- X:07 Y:09 n---zc
    jsr vectored                                                      ; 2030: 20 36 20     6  A:-- X:-- Y:09 ------ ; Jump through the vector at &0230
    sty l0074                                                         ; 2033: 84 74       .t  A:-- X:-- Y:09 ------
    rts                                                               ; 2035: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; Jump through the vector at &0230
; 
; On Exit:
;     Y is preserved
; ***************************************************************************************
; $2036 referenced 1 time by $2030
vectored:
    jmp (ind1v)                                                       ; 2036: 6c 30 02    l0. A:-- X:-- Y:-- ------

; A table of 5 bytes, indexed by Y (0 to 4), read at $2002
; $2039 referenced 1 time by $2002
l2039:
    .byte "HELLO"                                                     ; 2039: 48 45 4c... HEL
pydis_end:


; Label references by decreasing frequency:
;     OSWRCH:             3
;     OSRDCH:             1
;     c202e:              1
;     external_routine:   1
;     ind1v:              1
;     l0070:              1
;     l0071:              1
;     l0072:              1
;     l0073:              1
;     l0074:              1
;     l2039:              1
;     loop_c2002:         1
;     vectored:           1

; Automatically generated labels:
;     c202e
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l2039
;     loop_c2002

; Stats:
;
;     Total size (Code + Data) = 62 bytes
;     Code                     = 57 bytes (92%)
;     Data                     = 5 bytes (8%)
;
;     Number of instructions   = 26
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1

