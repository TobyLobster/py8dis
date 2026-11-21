; Assemble with Baron, which writes the program to the file named in its
; section (known_state_comments_baron), in the folder given with -p:
;     baron -p . known_state_comments_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070
l0071   = &0071
l0072   = &0072
l0073   = &0073
l0074   = &0074
l0075   = &0075
l0076   = &0076
l0077   = &0077
l0078   = &0078
l0079   = &0079
l007a   = &007a
l007b   = &007b
l007c   = &007c
l007d   = &007d
l007e   = &007e
l007f   = &007f
l0080   = &0080
l0081   = &0081
l0082   = &0082

section pydis, org = &2000, filename = "known_state_comments_baron"

.pydis_start
.start
    lda l0070                                                         ; 2000: a5 70       .p  A:-- X:-- Y:-- ------
    cmp l0071                                                         ; 2002: c5 71       .q  A:-- X:-- Y:-- ----??
    bne return_1                                                      ; 2004: d0 58       .X  A:-- X:-- Y:-- ----ZC
    adc #3                                                            ; 2006: 69 03       i.  A:-- X:-- Y:-- ------ ; Carry is set, so adding 4
    sta l0072                                                         ; 2008: 85 72       .r  A:-- X:-- Y:-- ------
    ldy l0073                                                         ; 200a: a4 73       .s  A:-- X:-- Y:-- ------
; &200c referenced 1 time by &200d
.loop_c200c
    iny                                                               ; 200c: c8          .   A:-- X:-- Y:-- ------
    bne loop_c200c                                                    ; 200d: d0 fd       ..  A:-- X:-- Y:00 n---Z-
    tya                                                               ; 200f: 98          .   A:00 X:-- Y:00 n---Z- ; A=0
    sta l0074                                                         ; 2010: 85 74       .t  A:00 X:-- Y:00 n---Z- [74]:00
    lda l0075                                                         ; 2012: a5 75       .u  A:-- X:-- Y:00 ------ [74]:00
    bcc return_1                                                      ; 2014: 90 48       .H  A:-- X:-- Y:00 -----C [74]:00
    ror a                                                             ; 2016: 6a          j   A:-- X:-- Y:00 N---z- [74]:00 ; Rotate in a set bit
    rol a                                                             ; 2017: 2a          *   A:-- X:-- Y:00 -----C [74]:00 ; Rotate set bit out (sets carry)
    sta l0076                                                         ; 2018: 85 76       .v  A:-- X:-- Y:00 -----C [74]:00
    rol l0082                                                         ; 201a: 26 82       &.  A:-- X:-- Y:00 ----z- [74]:00 ; Rotate in a set bit
    rts                                                               ; 201c: 60          `   A:-- X:-- Y:-- ------

.bits
    lda l0077                                                         ; 201d: a5 77       .w  A:-- X:-- Y:-- ------
    and #&3f ; '?'                                                    ; 201f: 29 3f       )?  A:-- X:-- Y:-- n-----
    asl a                                                             ; 2021: 0a          .   A:-- X:-- Y:-- n----c
    asl a                                                             ; 2022: 0a          .   A:-- X:-- Y:-- -----c ; Shift clear bit out (clears carry)
    adc #4                                                            ; 2023: 69 04       i.  A:-- X:-- Y:-- ------
    sta l0078                                                         ; 2025: 85 78       .x  A:-- X:-- Y:-- ------
    lda l0079                                                         ; 2027: a5 79       .y  A:-- X:-- Y:-- ------
    ora #&80                                                          ; 2029: 09 80       ..  A:-- X:-- Y:-- N---z-
    bmi c202d                                                         ; 202b: 30 00       0.  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &202d referenced 1 time by &202b
.c202d
    lda l007a                                                         ; 202d: a5 7a       .z  A:-- X:-- Y:-- ------
    and #1                                                            ; 202f: 29 01       ).  A:0- X:-- Y:-- n-----
    beq return_1                                                      ; 2031: f0 2b       .+  A:01 X:-- Y:-- n---z-
    tax                                                               ; 2033: aa          .   A:01 X:01 Y:-- n---z- ; X=1
    lda l007b                                                         ; 2034: a5 7b       .{  A:-- X:01 Y:-- ------
    bpl return_1                                                      ; 2036: 10 26       .&  A:-- X:01 Y:-- N-----
    asl a                                                             ; 2038: 0a          .   A:-- X:01 Y:-- -----C ; Shift set bit out (sets carry)
    rol l007c                                                         ; 2039: 26 7c       &|  A:-- X:01 Y:-- ----z- ; Rotate in a set bit
    lda l007d                                                         ; 203b: a5 7d       .}  A:-- X:01 Y:-- ------
    and #&0f                                                          ; 203d: 29 0f       ).  A:0- X:01 Y:-- n-----
    cmp #&10                                                          ; 203f: c9 10       ..  A:0- X:01 Y:-- N---zc
    bcc c2043                                                         ; 2041: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &2043 referenced 1 time by &2041
.c2043
    sec                                                               ; 2043: 38          8   A:0- X:01 Y:-- N---zC
    ror l007e                                                         ; 2044: 66 7e       f~  A:0- X:01 Y:-- N---z- ; Rotate in a set bit
    bmi c2048                                                         ; 2046: 30 00       0.  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &2048 referenced 1 time by &2046
.c2048
    lda l007f                                                         ; 2048: a5 7f       ..  A:-- X:01 Y:-- ------
    lsr a                                                             ; 204a: 4a          J   A:-- X:01 Y:-- n-----
    bpl c204d                                                         ; 204b: 10 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &204d referenced 1 time by &204b
.c204d
    cld                                                               ; 204d: d8          .   A:-- X:01 Y:-- n-d---
    lda l0080                                                         ; 204e: a5 80       ..  A:-- X:01 Y:-- --d---
    and #&0f                                                          ; 2050: 29 0f       ).  A:0- X:01 Y:-- n-d---
    clc                                                               ; 2052: 18          .   A:0- X:01 Y:-- n-d--c
    adc #&f0                                                          ; 2053: 69 f0       i.  A:f- X:01 Y:-- Nvd-zc
    bcc c2057                                                         ; 2055: 90 00       ..  A:-- X:-- Y:-- ------ ; ALWAYS branch

; &2057 referenced 1 time by &2055
.c2057
    lda l0081                                                         ; 2057: a5 81       ..  A:-- X:01 Y:-- -vd--c
    cmp #7                                                            ; 2059: c9 07       ..  A:-- X:01 Y:-- -vd-??
    ror a                                                             ; 205b: 6a          j   A:-- X:01 Y:-- -vd---
    tax                                                               ; 205c: aa          .   A:-- X:-- Y:-- -vd---
    rts                                                               ; 205d: 60          `   A:-- X:-- Y:-- ------

; &205e referenced 4 times by &2004, &2014, &2031, &2036
.return_1
    rts                                                               ; 205e: 60          `   A:-- X:-- Y:-- ------

.pydis_end


endsection

; Label references by decreasing frequency:
;     return_1:     4
;     c202d:        1
;     c2043:        1
;     c2048:        1
;     c204d:        1
;     c2057:        1
;     l0070:        1
;     l0071:        1
;     l0072:        1
;     l0073:        1
;     l0074:        1
;     l0075:        1
;     l0076:        1
;     l0077:        1
;     l0078:        1
;     l0079:        1
;     l007a:        1
;     l007b:        1
;     l007c:        1
;     l007d:        1
;     l007e:        1
;     l007f:        1
;     l0080:        1
;     l0081:        1
;     l0082:        1
;     loop_c200c:   1

; Automatically generated labels:
;     c202d
;     c2043
;     c2048
;     c204d
;     c2057
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
;     l007a
;     l007b
;     l007c
;     l007d
;     l007e
;     l007f
;     l0080
;     l0081
;     l0082
;     loop_c200c
;     return_1

; Stats:
;
;     Total size (Code + Data) = 95 bytes
;     Code                     = 95 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 56
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
