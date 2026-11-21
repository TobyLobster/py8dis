; Assemble with Baron, which writes the program to the file named in its
; section (declared_exits_baron), in the folder given with -p:
;     baron -p . declared_exits_baron.asm

; Constants
osword_read_line    = 0

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070
l0071   = &0071
l0072   = &0072
l0073   = &0073
l0074   = &0074
l0080   = &0080
l0081   = &0081

; OS vectors (&0200-&0235)
ind1v   = &0230

; User memory (&0e00-&7fff)
external_routine = &3000

; MOS entry points (&ffb3-&fff9)
OSRDCH  = &ffe0
OSWRCH  = &ffee
OSWORD  = &fff1

section pydis, org = &2000, filename = "declared_exits_baron"

.pydis_start
.start
    ; print message
    ldy #0                                                            ; 2000: a0 00       ..  A:-- X:-- Y:00 n---Z-
; &2002 referenced 1 time by &200b
.loop_c2002
    lda l205c,y                                                       ; 2002: b9 5c 20    .\  A:-- X:-- Y:0- ------
    jsr OSWRCH                                                        ; 2005: 20 ee ff     .. A:-- X:-- Y:0- --d--- ; Write character A
    iny                                                               ; 2008: c8          .   A:-- X:-- Y:0- n-d-z-
    cpy #5                                                            ; 2009: c0 05       ..  A:-- X:-- Y:0- --d-??
    bne loop_c2002                                                    ; 200b: d0 f5       ..  A:-- X:-- Y:05 n-d-ZC
    sty l0070                                                         ; 200d: 84 70       .p  A:-- X:-- Y:05 n-d-ZC [70]:05 ; Y=5
    ; Print "AA"
    lda #&41 ; 'A'                                                    ; 200f: a9 41       .A  A:41 X:-- Y:05 n-d-zC [70]:05
    jsr OSWRCH                                                        ; 2011: 20 ee ff     .. A:41 X:-- Y:05 --d--- [70]:05 ; Write character 65
    jsr OSWRCH                                                        ; 2014: 20 ee ff     .. A:41 X:-- Y:05 --d--- [70]:05 ; Write character 65
    lda #1                                                            ; 2017: a9 01       ..  A:01 X:-- Y:05 n-d-z- [70]:05
    clc                                                               ; 2019: 18          .   A:01 X:-- Y:05 n-d-zc [70]:05
    adc #2                                                            ; 201a: 69 02       i.  A:03 X:-- Y:05 nvd-zc [70]:05 ; A=3
    sta l0071                                                         ; 201c: 85 71       .q  A:03 X:-- Y:05 nvd-zc [70]:05 [71]:03
    ldx #3                                                            ; 201e: a2 03       ..  A:03 X:03 Y:05 nvd-zc [70]:05 [71]:03
    jsr OSRDCH                                                        ; 2020: 20 e0 ff     .. A:-- X:03 Y:05 --d--- [70]:05 [71]:03 ; Read a character from the current input stream
    stx l0072                                                         ; 2023: 86 72       .r  A:-- X:03 Y:05 --d--- [70]:05 [71]:03 [72]:03
    ldx #7                                                            ; 2025: a2 07       ..  A:-- X:07 Y:05 n-d-z- [70]:05 [71]:03 [72]:03
    jsr external_routine                                              ; 2027: 20 00 30     .0 A:-- X:07 Y:-- -----c [70]:05 [71]:03 [72]:03
    stx l0073                                                         ; 202a: 86 73       .s  A:-- X:07 Y:-- -----c [70]:05 [71]:03 [72]:03 [73]:07
    bcc c202e                                                         ; 202c: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &202e referenced 1 time by &202c
.c202e
    ldy #9                                                            ; 202e: a0 09       ..  A:-- X:07 Y:09 n---zc [70]:05 [71]:03 [72]:03 [73]:07
    jsr vectored                                                      ; 2030: 20 59 20     Y  A:-- X:-- Y:09 ------ ; Jump through the vector at &0230
    sty l0074                                                         ; 2033: 84 74       .t  A:-- X:-- Y:09 ------ [74]:09
    lda #0                                                            ; 2035: a9 00       ..  A:00 X:-- Y:09 n---Z- [74]:09
    sta l0080                                                         ; 2037: 85 80       ..  A:00 X:-- Y:09 n---Z- [74]:09 [80]:00
    sta l0081                                                         ; 2039: 85 81       ..  A:00 X:-- Y:09 n---Z- [74]:09 [80]:00 [81]:00
    lda #&42 ; 'B'                                                    ; 203b: a9 42       .B  A:42 X:-- Y:09 n---z- [74]:09 [80]:00 [81]:00
    jsr OSWRCH                                                        ; 203d: 20 ee ff     .. A:42 X:-- Y:09 --d--- [74]:09 [80]:00 [81]:00 ; Write character 66
    lda l0080                                                         ; 2040: a5 80       ..  A:00 X:-- Y:09 n-d-Z- [74]:09 [80]:00 [81]:00
    beq c2044                                                         ; 2042: f0 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &2044 referenced 1 time by &2042
.c2044
    jsr external_routine                                              ; 2044: 20 00 30     .0 A:-- X:-- Y:-- -----c [74]:09 [80]:00
    lda l0080                                                         ; 2047: a5 80       ..  A:00 X:-- Y:-- n---Zc [74]:09 [80]:00
    beq c204b                                                         ; 2049: f0 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &204b referenced 1 time by &2049
.c204b
    lda l0081                                                         ; 204b: a5 81       ..  A:-- X:-- Y:-- -----c [74]:09 [80]:00
    beq c204f                                                         ; 204d: f0 00       ..  A:-- X:-- Y:-- -----c [74]:09 [80]:00
; &204f referenced 1 time by &204d
.c204f
    lda #osword_read_line                                             ; 204f: a9 00       ..  A:00 X:-- Y:-- n---Zc [74]:09 [80]:00
    jsr OSWORD                                                        ; 2051: 20 f1 ff     .. A:-- X:-- Y:-- ------ ; Read line from input stream (exits with C=1 if ESCAPE pressed)
    lda l0080                                                         ; 2054: a5 80       ..  A:-- X:-- Y:-- ------
    beq return_1                                                      ; 2056: f0 00       ..  A:-- X:-- Y:-- ------
; &2058 referenced 1 time by &2056
.return_1
    rts                                                               ; 2058: 60          `   A:-- X:-- Y:-- ------

; ***************************************************************************************
; Jump through the vector at &0230
; 
; On Exit:
;     Y is preserved
; ***************************************************************************************
; &2059 referenced 1 time by &2030
.vectored
    jmp (ind1v)                                                       ; 2059: 6c 30 02    l0. A:-- X:-- Y:-- ------

; A table of 5 bytes, indexed by Y (0 to 4), read at &2002
; &205c referenced 1 time by &2002
.l205c
    equs "HELLO"                                                      ; 205c: 48 45 4c... HEL
.pydis_end


endsection

; Label references by decreasing frequency:
;     OSWRCH:             4
;     l0080:              4
;     external_routine:   2
;     l0081:              2
;     OSRDCH:             1
;     OSWORD:             1
;     c202e:              1
;     c2044:              1
;     c204b:              1
;     c204f:              1
;     ind1v:              1
;     l0070:              1
;     l0071:              1
;     l0072:              1
;     l0073:              1
;     l0074:              1
;     l205c:              1
;     loop_c2002:         1
;     return_1:           1
;     vectored:           1

; Automatically generated labels:
;     c202e
;     c2044
;     c204b
;     c204f
;     l0070
;     l0071
;     l0072
;     l0073
;     l0074
;     l0080
;     l0081
;     l205c
;     loop_c2002
;     return_1

; Stats:
;
;     Total size (Code + Data) = 97 bytes
;     Code                     = 92 bytes (95%)
;     Data                     = 5 bytes (5%)
;
;     Number of instructions   = 42
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1
