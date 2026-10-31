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

    * = $2000

pydis_start
start
    ldy #8                                                            // 2000: a0 08       ..  A:-- X:-- Y:08 n---z-
// $2002 referenced 1 time by $2003
loop_c2002
    dey                                                               // 2002: 88          .   A:-- X:-- Y:-- ------
    bne loop_c2002                                                    // 2003: d0 fd       ..  A:-- X:-- Y:00 n---Z-
    lda l0070                                                         // 2005: a5 70       .p  A:-- X:-- Y:00 ------
    cmp #$7b // '{'                                                   // 2007: c9 7b       .{  A:-- X:-- Y:00 ----??
    bne return_1                                                      // 2009: d0 1e       ..  A:7b X:-- Y:00 n---ZC
    ldx l0071                                                         // 200b: a6 71       .q  A:7b X:-- Y:00 -----C
    cpx #3                                                            // 200d: e0 03       ..  A:7b X:-- Y:00 ----??
    bne return_1                                                      // 200f: d0 18       ..  A:7b X:03 Y:00 n---ZC
    lda l0072                                                         // 2011: a5 72       .r  A:-- X:03 Y:00 -----C
    bne return_1                                                      // 2013: d0 14       ..  A:00 X:03 Y:00 n---ZC
    lda l0073                                                         // 2015: a5 73       .s  A:-- X:03 Y:00 -----C
    beq return_1                                                      // 2017: f0 10       ..  A:-- X:03 Y:00 ----zC
    ldy l0074                                                         // 2019: a4 74       .t  A:-- X:03 Y:-- -----C
    bne c201d                                                         // 201b: d0 00       ..  A:-- X:03 Y:-- -----C
// $201d referenced 1 time by $201b
c201d
    tax                                                               // 201d: aa          .   A:-- X:-- Y:-- ------
    bit l0075                                                         // 201e: 24 75       $u  A:-- X:-- Y:-- ------
    bne return_1                                                      // 2020: d0 07       ..  A:-- X:-- Y:-- ----Z-
    lda l0076                                                         // 2022: a5 76       .v  A:-- X:-- Y:-- ------
    sta l0077                                                         // 2024: 85 77       .w  A:-- X:-- Y:-- ------
    bne return_1                                                      // 2026: d0 01       ..  A:00 X:-- Y:-- n---Z-
    rts                                                               // 2028: 60          `   A:-- X:-- Y:-- ------

// $2029 referenced 6 times by $2009, $200f, $2013, $2017, $2020, $2026
return_1
    rts                                                               // 2029: 60          `   A:-- X:-- Y:-- ------

pydis_end


// Label references by decreasing frequency:
//     return_1:     6
//     c201d:        1
//     l0070:        1
//     l0071:        1
//     l0072:        1
//     l0073:        1
//     l0074:        1
//     l0075:        1
//     l0076:        1
//     l0077:        1
//     loop_c2002:   1

// Automatically generated labels:
//     c201d
//     l0070
//     l0071
//     l0072
//     l0073
//     l0074
//     l0075
//     l0076
//     l0077
//     loop_c2002
//     return_1

// Stats:
//
//     Total size (Code + Data) = 42 bytes
//     Code                     = 42 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 23
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

