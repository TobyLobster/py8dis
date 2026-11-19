// Memory locations

// Zero page ($0000-$00ff)
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
l007a   = $007a
l007b   = $007b
l007c   = $007c
l007d   = $007d
l007e   = $007e
l007f   = $007f
l0080   = $0080
l0081   = $0081

    * = $2000

pydis_start
start
    lda l0070                                                         // 2000: a5 70       .p  A:-- X:-- Y:-- ------
    cmp l0071                                                         // 2002: c5 71       .q  A:-- X:-- Y:-- ----??
    bne return_1                                                      // 2004: d0 56       .V  A:-- X:-- Y:-- ----ZC
    adc #3                                                            // 2006: 69 03       i.  A:-- X:-- Y:-- ------ // Carry is set, so adding 4
    sta l0072                                                         // 2008: 85 72       .r  A:-- X:-- Y:-- ------
    ldy l0073                                                         // 200a: a4 73       .s  A:-- X:-- Y:-- ------
// $200c referenced 1 time by $200d
loop_c200c
    iny                                                               // 200c: c8          .   A:-- X:-- Y:-- ------
    bne loop_c200c                                                    // 200d: d0 fd       ..  A:-- X:-- Y:00 n---Z-
    tya                                                               // 200f: 98          .   A:00 X:-- Y:00 n---Z- // A=0
    sta l0074                                                         // 2010: 85 74       .t  A:00 X:-- Y:00 n---Z-
    lda l0075                                                         // 2012: a5 75       .u  A:-- X:-- Y:00 ------
    bcc return_1                                                      // 2014: 90 46       .F  A:-- X:-- Y:00 -----C
    ror                                                               // 2016: 6a          j   A:-- X:-- Y:00 N---z- // Rotate in a set bit
    rol                                                               // 2017: 2a          *   A:-- X:-- Y:00 -----C // Rotate set bit out (sets carry)
    sta l0076                                                         // 2018: 85 76       .v  A:-- X:-- Y:00 -----C
    rts                                                               // 201a: 60          `   A:-- X:-- Y:-- ------

bits
    lda l0077                                                         // 201b: a5 77       .w  A:-- X:-- Y:-- ------
    and #$3f // '?'                                                   // 201d: 29 3f       )?  A:-- X:-- Y:-- n-----
    asl                                                               // 201f: 0a          .   A:-- X:-- Y:-- n----c
    asl                                                               // 2020: 0a          .   A:-- X:-- Y:-- -----c // Shift clear bit out (clears carry)
    adc #4                                                            // 2021: 69 04       i.  A:-- X:-- Y:-- ------
    sta l0078                                                         // 2023: 85 78       .x  A:-- X:-- Y:-- ------
    lda l0079                                                         // 2025: a5 79       .y  A:-- X:-- Y:-- ------
    ora #$80                                                          // 2027: 09 80       ..  A:-- X:-- Y:-- N---z-
    bmi c202b                                                         // 2029: 30 00       0.  A:-- X:-- Y:-- ------ // ALWAYS branch

// $202b referenced 1 time by $2029
c202b
    lda l007a                                                         // 202b: a5 7a       .z  A:-- X:-- Y:-- ------
    and #1                                                            // 202d: 29 01       ).  A:0- X:-- Y:-- n-----
    beq return_1                                                      // 202f: f0 2b       .+  A:01 X:-- Y:-- n---z-
    tax                                                               // 2031: aa          .   A:01 X:01 Y:-- n---z- // X=1
    lda l007b                                                         // 2032: a5 7b       .{  A:-- X:01 Y:-- ------
    bpl return_1                                                      // 2034: 10 26       .&  A:-- X:01 Y:-- N-----
    asl                                                               // 2036: 0a          .   A:-- X:01 Y:-- -----C // Shift set bit out (sets carry)
    rol l007c                                                         // 2037: 26 7c       &|  A:-- X:01 Y:-- ----z- // Rotate in a set bit
    lda l007d                                                         // 2039: a5 7d       .}  A:-- X:01 Y:-- ------
    and #$0f                                                          // 203b: 29 0f       ).  A:0- X:01 Y:-- n-----
    cmp #$10                                                          // 203d: c9 10       ..  A:0- X:01 Y:-- N---zc
    bcc c2041                                                         // 203f: 90 00       ..  A:-- X:-- Y:-- ------ // ALWAYS branch

// $2041 referenced 1 time by $203f
c2041
    sec                                                               // 2041: 38          8   A:0- X:01 Y:-- N---zC
    ror l007e                                                         // 2042: 66 7e       f~  A:0- X:01 Y:-- N---z- // Rotate in a set bit
    bmi c2046                                                         // 2044: 30 00       0.  A:-- X:-- Y:-- ------ // ALWAYS branch

// $2046 referenced 1 time by $2044
c2046
    lda l007f                                                         // 2046: a5 7f       ..  A:-- X:01 Y:-- ------
    lsr                                                               // 2048: 4a          J   A:-- X:01 Y:-- n-----
    bpl c204b                                                         // 2049: 10 00       ..  A:-- X:-- Y:-- ------ // ALWAYS branch

// $204b referenced 1 time by $2049
c204b
    cld                                                               // 204b: d8          .   A:-- X:01 Y:-- n-d---
    lda l0080                                                         // 204c: a5 80       ..  A:-- X:01 Y:-- --d---
    and #$0f                                                          // 204e: 29 0f       ).  A:0- X:01 Y:-- n-d---
    clc                                                               // 2050: 18          .   A:0- X:01 Y:-- n-d--c
    adc #$f0                                                          // 2051: 69 f0       i.  A:f- X:01 Y:-- N-d-zc
    bcc c2055                                                         // 2053: 90 00       ..  A:-- X:-- Y:-- ------ // ALWAYS branch

// $2055 referenced 1 time by $2053
c2055
    lda l0081                                                         // 2055: a5 81       ..  A:-- X:01 Y:-- --d--c
    cmp #7                                                            // 2057: c9 07       ..  A:-- X:01 Y:-- --d-??
    ror                                                               // 2059: 6a          j   A:-- X:01 Y:-- --d---
    tax                                                               // 205a: aa          .   A:-- X:-- Y:-- --d---
    rts                                                               // 205b: 60          `   A:-- X:-- Y:-- ------

// $205c referenced 4 times by $2004, $2014, $202f, $2034
return_1
    rts                                                               // 205c: 60          `   A:-- X:-- Y:-- ------

pydis_end


// Label references by decreasing frequency:
//     return_1:     4
//     c202b:        1
//     c2041:        1
//     c2046:        1
//     c204b:        1
//     c2055:        1
//     l0070:        1
//     l0071:        1
//     l0072:        1
//     l0073:        1
//     l0074:        1
//     l0075:        1
//     l0076:        1
//     l0077:        1
//     l0078:        1
//     l0079:        1
//     l007a:        1
//     l007b:        1
//     l007c:        1
//     l007d:        1
//     l007e:        1
//     l007f:        1
//     l0080:        1
//     l0081:        1
//     loop_c200c:   1

// Automatically generated labels:
//     c202b
//     c2041
//     c2046
//     c204b
//     c2055
//     l0070
//     l0071
//     l0072
//     l0073
//     l0074
//     l0075
//     l0076
//     l0077
//     l0078
//     l0079
//     l007a
//     l007b
//     l007c
//     l007d
//     l007e
//     l007f
//     l0080
//     l0081
//     loop_c200c
//     return_1

// Stats:
//
//     Total size (Code + Data) = 93 bytes
//     Code                     = 93 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 55
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

