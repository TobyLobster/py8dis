; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071
l0072   = $0072
l0073   = $0073
l0074   = $0074
l0075   = $0075
l0076   = $0076
l0077   = $0077
l0078   = $0078
l0079   = $0079

; Stack ($0100-$01ff)
l0101   = $0101

    * = $2000

pydis_start
start
    ldx #4                                                            ; 2000: a2 04       ..  A:-- X:04 Y:-- n---z-
    ldy #6                                                            ; 2002: a0 06       ..  A:-- X:04 Y:06 n---z-
    jsr c2038                                                         ; 2004: 20 38 20     8  A:-- X:04 Y:06 -----c
    stx l0070                                                         ; 2007: 86 70       .p  A:-- X:04 Y:06 -----c [70]:04
    bcc c200b                                                         ; 2009: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $200b referenced 1 time by $2009
c200b
    jsr sub_c2040                                                     ; 200b: 20 40 20     @  A:-0 X:04 Y:06 -----c [70]:04
    and #$7f                                                          ; 200e: 29 7f       ).  A:00 X:04 Y:06 n---Zc [70]:04 ; A=0
    sta l0071                                                         ; 2010: 85 71       .q  A:00 X:04 Y:06 n---Zc [70]:04 [71]:00
    jsr sub_c204a                                                     ; 2012: 20 4a 20     J  A:-- X:04 Y:-- -----c [70]:04 [71]:00
    bcc c2017                                                         ; 2015: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $2017 referenced 1 time by $2015
c2017
    ldx #9                                                            ; 2017: a2 09       ..  A:-- X:09 Y:-- n---zc [70]:04 [71]:00
    jsr sub_c204f                                                     ; 2019: 20 4f 20     O  A:-- X:-- Y:-- ------
    stx l0072                                                         ; 201c: 86 72       .r  A:-- X:-- Y:-- ------
    lda #1                                                            ; 201e: a9 01       ..  A:01 X:-- Y:-- n---z-
    ldx #2                                                            ; 2020: a2 02       ..  A:01 X:02 Y:-- n---z-
    ldy #3                                                            ; 2022: a0 03       ..  A:01 X:02 Y:03 n---z-
    clc                                                               ; 2024: 18          .   A:01 X:02 Y:03 n---zc
    jsr sub_c2058                                                     ; 2025: 20 58 20     X  A:01 X:02 Y:03 n---zc
    sta l0075                                                         ; 2028: 85 75       .u  A:01 X:02 Y:03 n---zc [75]:01 ; A=1
    stx l0076                                                         ; 202a: 86 76       .v  A:01 X:02 Y:03 n---zc [75]:01 [76]:02 ; X=2
    sty l0077                                                         ; 202c: 84 77       .w  A:01 X:02 Y:03 n---zc [75]:01 [76]:02 [77]:03 ; Y=3
    bcc c2030                                                         ; 202e: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; $2030 referenced 1 time by $202e
c2030
    lda #1                                                            ; 2030: a9 01       ..  A:01 X:02 Y:03 n---zc [75]:01 [76]:02 [77]:03
    jsr sub_c206a                                                     ; 2032: 20 6a 20     j  A:-- X:-- Y:03 -----c [75]:01 [76]:02 [77]:03
    sta l0078                                                         ; 2035: 85 78       .x  A:-- X:-- Y:03 -----c [75]:01 [76]:02 [77]:03
    rts                                                               ; 2037: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; On Exit:
;     C: clear
;     X is preserved
; ***************************************************************************************
; $2038 referenced 2 times by $2004, $204c
c2038
    lda l0073                                                         ; 2038: a5 73       .s  A:-- X:-- Y:-- ------
    beq c203e                                                         ; 203a: f0 02       ..  A:-- X:-- Y:-- ----z-
    clc                                                               ; 203c: 18          .   A:-- X:-- Y:-- ----zc
    rts                                                               ; 203d: 60          `   A:-- X:-- Y:-- ------

; $203e referenced 1 time by $203a
c203e
    clc                                                               ; 203e: 18          .   A:00 X:-- Y:-- n---Zc
    rts                                                               ; 203f: 60          `   A:-- X:-- Y:-- ------

; $2040 referenced 1 time by $200b
sub_c2040
    lda l0074                                                         ; 2040: a5 74       .t  A:-- X:-- Y:-- ------
    bmi c2047                                                         ; 2042: 30 03       0.  A:-- X:-- Y:-- n-----
    lda #0                                                            ; 2044: a9 00       ..  A:00 X:-- Y:-- n---Z-
    rts                                                               ; 2046: 60          `   A:-- X:-- Y:-- ------

; $2047 referenced 1 time by $2042
c2047
    lda #$80                                                          ; 2047: a9 80       ..  A:80 X:-- Y:-- N---z-
    rts                                                               ; 2049: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; On Exit:
;     C: clear
; ***************************************************************************************
; $204a referenced 1 time by $2012
sub_c204a
    ldy #1                                                            ; 204a: a0 01       ..  A:-- X:-- Y:01 n---z-
    jmp c2038                                                         ; 204c: 4c 38 20    L8  A:-- X:-- Y:-- ------

; $204f referenced 1 time by $2019
sub_c204f
    jsr sub_c2055                                                     ; 204f: 20 55 20     U  A:-- X:-- Y:-- ------
    ldx #2                                                            ; 2052: a2 02       ..  A:-- X:02 Y:-- n---z-
    rts                                                               ; 2054: 60          `   A:-- X:-- Y:-- ------

; $2055 referenced 1 time by $204f
sub_c2055
    pla                                                               ; 2055: 68          h   A:-- X:-- Y:-- ------
    pla                                                               ; 2056: 68          h   A:-- X:-- Y:-- ------
    rts                                                               ; 2057: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; On Exit:
;     A, X, Y and C are preserved
; ***************************************************************************************
; $2058 referenced 1 time by $2025
sub_c2058
    ; push flags,A,X,Y onto the stack
    php                                                               ; 2058: 08          .   A:-- X:-- Y:-- ------
    pha                                                               ; 2059: 48          H   A:-- X:-- Y:-- ------
    txa                                                               ; 205a: 8a          .   A:-- X:-- Y:-- ------
    pha                                                               ; 205b: 48          H   A:-- X:-- Y:-- ------
    tya                                                               ; 205c: 98          .   A:-- X:-- Y:-- ------
    pha                                                               ; 205d: 48          H   A:-- X:-- Y:-- ------
    lda l0079                                                         ; 205e: a5 79       .y  A:-- X:-- Y:-- ------ ; Redundant instruction?
    tax                                                               ; 2060: aa          .   A:-- X:-- Y:-- ------ ; Redundant instruction?
    tay                                                               ; 2061: a8          .   A:-- X:-- Y:-- ------ ; Redundant instruction?
    sec                                                               ; 2062: 38          8   A:-- X:-- Y:-- -----C ; Redundant instruction?
    ; pull flags,A,X,Y from the stack
    pla                                                               ; 2063: 68          h   A:-- X:-- Y:-- -----C
    tay                                                               ; 2064: a8          .   A:-- X:-- Y:-- -----C
    pla                                                               ; 2065: 68          h   A:-- X:-- Y:-- -----C
    tax                                                               ; 2066: aa          .   A:-- X:-- Y:-- -----C
    pla                                                               ; 2067: 68          h   A:-- X:-- Y:-- -----C
    plp                                                               ; 2068: 28          (   A:-- X:-- Y:-- ------
    rts                                                               ; 2069: 60          `   A:-- X:-- Y:-- ------

; $206a referenced 1 time by $2032
sub_c206a
    pha                                                               ; 206a: 48          H   A:-- X:-- Y:-- ------
    lda #7                                                            ; 206b: a9 07       ..  A:07 X:-- Y:-- n---z-
    tsx                                                               ; 206d: ba          .   A:07 X:-- Y:-- ------
    sta l0101,x                                                       ; 206e: 9d 01 01    ... A:07 X:-- Y:-- ------
    pla                                                               ; 2071: 68          h   A:-- X:-- Y:-- ------
    rts                                                               ; 2072: 60          `   A:-- X:-- Y:-- ------

pydis_end


; Label references by decreasing frequency:
;     c2038:       2
;     c200b:       1
;     c2017:       1
;     c2030:       1
;     c203e:       1
;     c2047:       1
;     l0070:       1
;     l0071:       1
;     l0072:       1
;     l0073:       1
;     l0074:       1
;     l0075:       1
;     l0076:       1
;     l0077:       1
;     l0078:       1
;     l0079:       1
;     l0101:       1
;     sub_c2040:   1
;     sub_c204a:   1
;     sub_c204f:   1
;     sub_c2055:   1
;     sub_c2058:   1
;     sub_c206a:   1

; Automatically generated labels:
;     c200b
;     c2017
;     c2030
;     c2038
;     c203e
;     c2047
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0075
;     l0076
;     l0077
;     l0078
;     l0079
;     l0101
;     sub_c2040
;     sub_c204a
;     sub_c204f
;     sub_c2055
;     sub_c2058
;     sub_c206a

; Stats:
;
;     Total size (Code + Data) = 115 bytes
;     Code                     = 115 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 69
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

