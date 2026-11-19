; Memory locations

; Zero page ($0000-$00ff)
l0070   = $70
l0071   = $71
l0072   = $72
l0073   = $73
l0074   = $74

    * = $2000

pydis_start
start
    ldx #4                                                            ; 2000: a2 04       ..  A:-- X:04 Y:-- n---z-
    ldy #6                                                            ; 2002: a0 06       ..  A:-- X:04 Y:06 n---z-
    jsr c201f                                                         ; 2004: 20 1f 20     .  A:-- X:04 Y:06 -----c
    stx l0070                                                         ; 2007: 86 70       .p  A:-- X:04 Y:06 -----c
    bcc c200b                                                         ; 2009: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $200b referenced 1 time by $2009
c200b
    jsr sub_c2027                                                     ; 200b: 20 27 20     '  A:-0 X:04 Y:06 -----c
    and #$7f                                                          ; 200e: 29 7f       ).  A:00 X:04 Y:06 n---Zc ; A=0
    sta l0071                                                         ; 2010: 85 71       .q  A:00 X:04 Y:06 n---Zc
    jsr sub_c2031                                                     ; 2012: 20 31 20     1  A:-- X:04 Y:-- -----c
    bcc c2017                                                         ; 2015: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $2017 referenced 1 time by $2015
c2017
    ldx #9                                                            ; 2017: a2 09       ..  A:-- X:09 Y:-- n---zc
    jsr sub_c2036                                                     ; 2019: 20 36 20     6  A:-- X:-- Y:-- ------
    stx l0072                                                         ; 201c: 86 72       .r  A:-- X:-- Y:-- ------
    rts                                                               ; 201e: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; On Exit:
;     X: (preserved)
;     C: clear
; ***************************************************************************************
; $201f referenced 2 times by $2004, $2033
c201f
    lda l0073                                                         ; 201f: a5 73       .s  A:-- X:-- Y:-- ------
    beq c2025                                                         ; 2021: f0 02       ..  A:-- X:-- Y:-- ----z-
    clc                                                               ; 2023: 18          .   A:-- X:-- Y:-- ----zc
    rts                                                               ; 2024: 60          `   A:-- X:-- Y:-- ------

; $2025 referenced 1 time by $2021
c2025
    clc                                                               ; 2025: 18          .   A:00 X:-- Y:-- n---Zc
    rts                                                               ; 2026: 60          `   A:-- X:-- Y:-- ------

; $2027 referenced 1 time by $200b
sub_c2027
    lda l0074                                                         ; 2027: a5 74       .t  A:-- X:-- Y:-- ------
    bmi c202e                                                         ; 2029: 30 03       0.  A:-- X:-- Y:-- n-----
    lda #0                                                            ; 202b: a9 00       ..  A:00 X:-- Y:-- n---Z-
    rts                                                               ; 202d: 60          `   A:-- X:-- Y:-- ------

; $202e referenced 1 time by $2029
c202e
    lda #$80                                                          ; 202e: a9 80       ..  A:80 X:-- Y:-- N---z-
    rts                                                               ; 2030: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; On Exit:
;     C: clear
; ***************************************************************************************
; $2031 referenced 1 time by $2012
sub_c2031
    ldy #1                                                            ; 2031: a0 01       ..  A:-- X:-- Y:01 n---z-
    jmp c201f                                                         ; 2033: 4c 1f 20    L.  A:-- X:-- Y:-- ------

; $2036 referenced 1 time by $2019
sub_c2036
    jsr sub_c203c                                                     ; 2036: 20 3c 20     <  A:-- X:-- Y:-- ------
    ldx #2                                                            ; 2039: a2 02       ..  A:-- X:02 Y:-- n---z-
    rts                                                               ; 203b: 60          `   A:-- X:-- Y:-- ------

; $203c referenced 1 time by $2036
sub_c203c
    pla                                                               ; 203c: 68          h   A:-- X:-- Y:-- ------
    pla                                                               ; 203d: 68          h   A:-- X:-- Y:-- ------
    rts                                                               ; 203e: 60          `   A:-- X:-- Y:-- ------

pydis_end


; Label references by decreasing frequency:
;     c201f:       2
;     c200b:       1
;     c2017:       1
;     c2025:       1
;     c202e:       1
;     l0070:       1
;     l0071:       1
;     l0072:       1
;     l0073:       1
;     l0074:       1
;     sub_c2027:   1
;     sub_c2031:   1
;     sub_c2036:   1
;     sub_c203c:   1

; Automatically generated labels:
;     c200b
;     c2017
;     c201f
;     c2025
;     c202e
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     sub_c2027
;     sub_c2031
;     sub_c2036
;     sub_c203c

; Stats:
;
;     Total size (Code + Data) = 63 bytes
;     Code                     = 63 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 34
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

