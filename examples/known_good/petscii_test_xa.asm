// Memory locations
l0400   = $0400
chrout  = $ffd2

    * = $c000

pydis_start
start
    lda #$93                                                          // c000: a9 93       ..
    jsr chrout                                                        // c002: 20 d2 ff     R.
    ldx #0                                                            // c005: a2 00       ..
// $c007 referenced 1 time by $c010
loop_cc007
    lda lc023,x                                                       // c007: bd 23 c0    .#.
    beq cc012                                                         // c00a: f0 06       ..
    jsr chrout                                                        // c00c: 20 d2 ff     R.
    inx                                                               // c00f: e8          .
    bne loop_cc007                                                    // c010: d0 f5       P.
// $c012 referenced 1 time by $c00a
cc012
    // Copy 21 bytes of memory from lc04e to l0400
    ldx #$14                                                          // c012: a2 14       ..
// $c014 referenced 1 time by $c01b
loop_cc014
    lda lc04e,x                                                       // c014: bd 4e c0    .n.
    sta l0400,x                                                       // c017: 9d 00 04    ...
    dex                                                               // c01a: ca          J
    bpl loop_cc014                                                    // c01b: 10 f7       ..
    lda #$41 // 'a'                                                   // c01d: a9 41       .a
    jsr chrout                                                        // c01f: 20 d2 ff     R.
    rts                                                               // c022: 60          .

// $c023 referenced 1 time by $c007
lc023
    .byt $93, $c8, $45, $4c, $4c, $4f, $2c // petscii $93, "Hello,"   // c023: 93 c8 45... .He
    .byt $20, $d7, $4f, $52, $4c, $44, $21, $20 // petscii " World! " // c02a: 20 d7 4f...  Wo
    .byt $d3, $41, $59, $20, $22, $48 // petscii "Say ", $22, "h"     // c032: d3 41 59... Say
    .byt $49, $22, $0d, 0 // petscii "i", $22, $0d, $00               // c038: 49 22 0d... i".
    .byt $43, $4f, $53, $54, $3a, $20, $5c // petscii "cost: ", $5c   // c03c: 43 4f 53... cos
    .byt $35, $20, $5e, $5f, $60 // petscii "5 ", $5e, $5f, $60       // c043: 35 20 5e... 5 .
    .byt $7b, $a0, $b0, $db, $ff // petscii $7b, $a0, $b0, $db, $ff   // c048: 7b a0 b0... ...
    .byt 0 // petscii $00                                             // c04d: 00          .
// $c04e referenced 1 time by $c014
lc04e
    .byt 0, $20, $53, 3, $0f, $12, 5, $20, $1b // screen "@ Score ["  // c04e: 00 20 53... @ S
    .byt $30, $30, $30, $1d, $20, $4c, 9, $16 // screen "000] Liv"    // c057: 30 30 30... 000
    .byt 5, $13, $20, $33 // screen "es 3"                            // c05f: 05 13 20... es
    .asc "ASCII text", 0                                              // c063: 41 53 43... ASC
    .byt $45, $4e, $44, $80 + $78 // petscii "end", $f8               // c06e: 45 4e 44... end
    .byt $46, $4f, $55, $4e, $44, $20, $42, $59 // petscii "found by" // c072: 46 4f 55... fou
    .byt $20, $41, $55, $54, $4f, $53, $54, $52 // petscii " autostr" // c07a: 20 41 55...  au
    .byt $49, $4e, $47 // petscii "ing"                               // c082: 49 4e 47    ing
    .byt 0                                                            // c085: 00          .
    .asc "o", $80 + 'k'                                               // c086: 6f eb       o.
pydis_end

#if ($80 + $78) <> $f8
#error Assertion failed: $80 + $78 == $f8
#endif
#if ($80 + 'k') <> $eb
#error Assertion failed: $80 + 'k' == $eb
#endif

// Label references by decreasing frequency:
//     chrout:       3
//     cc012:        1
//     l0400:        1
//     lc023:        1
//     lc04e:        1
//     loop_cc007:   1
//     loop_cc014:   1

// Automatically generated labels:
//     cc012
//     l0400
//     lc023
//     lc04e
//     loop_cc007
//     loop_cc014

// Stats:
//
//     Total size (Code + Data) = 136 bytes
//     Code                     = 35 bytes (26%)
//     Data                     = 101 bytes (74%)
//
//     Number of instructions   = 16
//     Number of data bytes     = 1 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 100 bytes
//     Number of strings        = 7

