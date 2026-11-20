// Memory locations

// Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071
l0072   = $0072

    * = $2000

pydis_start
start
    jsr sub_c2010                                                     // 2000: 20 10 20     .  A:05 X:-- Y:05 n---z-
    jsr sub_c201c                                                     // 2003: 20 1c 20     .  A:-- X:-- Y:-- ------
    jsr sub_c202e                                                     // 2006: 20 2e 20     .  A:-- X:-- Y:-- ------
    jsr sub_c2049                                                     // 2009: 20 49 20     I  A:-- X:-- Y:-- ------
    jsr sub_c2050                                                     // 200c: 20 50 20     P  A:-- X:-- Y:07 ------
    rts                                                               // 200f: 60          `   A:-- X:-- Y:-- ------

// $2010 referenced 1 time by $2000
sub_c2010
    lda l0070                                                         // 2010: a5 70       .p  A:-- X:-- Y:-- ------
    beq c2018                                                         // 2012: f0 04       ..  A:-- X:-- Y:-- ----z-
    ldy #5                                                            // 2014: a0 05       ..  A:-- X:-- Y:05 n---z-
    bne c201a                                                         // 2016: d0 02       ..  A:-- X:-- Y:-- ------ // ALWAYS branch

// $2018 referenced 1 time by $2012
c2018
    ldy #5                                                            // 2018: a0 05       ..  A:00 X:-- Y:05 n---z-
// $201a referenced 1 time by $2016
c201a
    tya                                                               // 201a: 98          .   A:05 X:-- Y:05 n---z- // A=5
    rts                                                               // 201b: 60          `   A:-- X:-- Y:-- ------

// $201c referenced 1 time by $2003
sub_c201c
    lda l0071                                                         // 201c: a5 71       .q  A:-- X:-- Y:-- ------
    cmp #3                                                            // 201e: c9 03       ..  A:-- X:-- Y:-- ----??
    bcc c2023                                                         // 2020: 90 01       ..  A:-- X:-- Y:-- ----?C
    rts                                                               // 2022: 60          `   A:-- X:-- Y:-- ------

// $2023 referenced 1 time by $2020
c2023
    asl                                                               // 2023: 0a          .   A:0- X:-- Y:-- n----c
    tax                                                               // 2024: aa          .   A:0- X:0- Y:-- n----c
    lda l205d,x                                                       // 2025: bd 5d 20    .]  A:-- X:0- Y:-- -----c
    pha                                                               // 2028: 48          H   A:-- X:0- Y:-- -----c
    lda l205c,x                                                       // 2029: bd 5c 20    .\  A:-- X:0- Y:-- -----c
    pha                                                               // 202c: 48          H   A:-- X:0- Y:-- -----c
    rts                                                               // 202d: 60          `   A:-- X:-- Y:-- ------

// $202e referenced 1 time by $2006
sub_c202e
    lda l0072                                                         // 202e: a5 72       .r  A:-- X:-- Y:-- ------
    ldx #0                                                            // 2030: a2 00       ..  A:-- X:00 Y:-- n---Z-
    // Search 4 bytes from l2058 for A
// $2032 referenced 1 time by $203a
loop_c2032
    cmp l2058,x                                                       // 2032: dd 58 20    .X  A:-- X:0- Y:-- ----??
    beq c203d                                                         // 2035: f0 06       ..  A:-- X:0- Y:-- ----z?
    inx                                                               // 2037: e8          .   A:-- X:0- Y:-- n---z-
    cpx #4                                                            // 2038: e0 04       ..  A:-- X:0- Y:-- ----??
    bne loop_c2032                                                    // 203a: d0 f6       ..  A:-- X:04 Y:-- n---ZC
    rts                                                               // 203c: 60          `   A:-- X:-- Y:-- ------

// $203d referenced 1 time by $2035
c203d
    txa                                                               // 203d: 8a          .   A:0- X:0- Y:-- n----C
    asl                                                               // 203e: 0a          .   A:0- X:0- Y:-- n----c
    tax                                                               // 203f: aa          .   A:0- X:0- Y:-- n----c
    lda l2063,x                                                       // 2040: bd 63 20    .c  A:-- X:0- Y:-- -----c
    pha                                                               // 2043: 48          H   A:-- X:0- Y:-- -----c
    lda l2062,x                                                       // 2044: bd 62 20    .b  A:-- X:0- Y:-- -----c
    pha                                                               // 2047: 48          H   A:-- X:0- Y:-- -----c
    rts                                                               // 2048: 60          `   A:-- X:-- Y:-- ------

// $2049 referenced 1 time by $2009
sub_c2049
    ldy #6                                                            // 2049: a0 06       ..  A:-- X:-- Y:06 n---z-
    jmp c204e                                                         // 204b: 4c 4e 20    LN  A:-- X:-- Y:-- ------

// $204e referenced 1 time by $204b
c204e
    tya                                                               // 204e: 98          .   A:-- X:-- Y:-- ------
    rts                                                               // 204f: 60          `   A:-- X:-- Y:-- ------

// $2050 referenced 1 time by $200c
sub_c2050
    ldy #7                                                            // 2050: a0 07       ..  A:-- X:-- Y:07 n---z-
    jsr sub_c2056                                                     // 2052: 20 56 20     V  A:-- X:-- Y:07 ------
    rts                                                               // 2055: 60          `   A:-- X:-- Y:-- ------

// $2056 referenced 1 time by $2052
sub_c2056
    tya                                                               // 2056: 98          .   A:-- X:-- Y:-- ------
    rts                                                               // 2057: 60          `   A:-- X:-- Y:-- ------

// $2058 referenced 1 time by $2032
l2058
    .asc "ABCD"                                                       // 2058: 41 42 43... ABC
// A jump table of 3 entries (each the address minus 1, for the RTS at $202d)
// $205c referenced 1 time by $2029
l205c
l205d = l205c+1
    .word sub_c206a - 1                                               // 205c: 69 20       i
// $205d referenced 1 time by $2025
    .word sub_c206d - 1                                               // 205e: 6c 20       l
    .word sub_c2070 - 1                                               // 2060: 6f 20       o
// A jump table of 4 entries (each the address minus 1, for the RTS at $2048)
// $2062 referenced 1 time by $2044
l2062
l2063 = l2062+1
    .word sub_c2073 - 1                                               // 2062: 72 20       r
// $2063 referenced 1 time by $2040
    .word sub_c2076 - 1                                               // 2064: 75 20       u
    .word sub_c2079 - 1                                               // 2066: 78 20       x
    .word sub_c207c - 1                                               // 2068: 7b 20       {

sub_c206a
    lda #$1a                                                          // 206a: a9 1a       ..  A:1a X:-- Y:-- n---z-
    rts                                                               // 206c: 60          `   A:-- X:-- Y:-- ------

sub_c206d
    lda #$1b                                                          // 206d: a9 1b       ..  A:1b X:-- Y:-- n---z-
    rts                                                               // 206f: 60          `   A:-- X:-- Y:-- ------

sub_c2070
    lda #$1c                                                          // 2070: a9 1c       ..  A:1c X:-- Y:-- n---z-
    rts                                                               // 2072: 60          `   A:-- X:-- Y:-- ------

sub_c2073
    lda #$2a // '*'                                                   // 2073: a9 2a       .*  A:2a X:-- Y:-- n---z-
    rts                                                               // 2075: 60          `   A:-- X:-- Y:-- ------

sub_c2076
    lda #$2b // '+'                                                   // 2076: a9 2b       .+  A:2b X:-- Y:-- n---z-
    rts                                                               // 2078: 60          `   A:-- X:-- Y:-- ------

sub_c2079
    lda #$2c // ','                                                   // 2079: a9 2c       .,  A:2c X:-- Y:-- n---z-
    rts                                                               // 207b: 60          `   A:-- X:-- Y:-- ------

sub_c207c
    lda #$2d // '-'                                                   // 207c: a9 2d       .-  A:2d X:-- Y:-- n---z-
    rts                                                               // 207e: 60          `   A:-- X:-- Y:-- ------

pydis_end

#if (sub_c206a - 1) <> $2069
#error Assertion failed: sub_c206a - 1 == $2069
#endif
#if (sub_c206d - 1) <> $206c
#error Assertion failed: sub_c206d - 1 == $206c
#endif
#if (sub_c2070 - 1) <> $206f
#error Assertion failed: sub_c2070 - 1 == $206f
#endif
#if (sub_c2073 - 1) <> $2072
#error Assertion failed: sub_c2073 - 1 == $2072
#endif
#if (sub_c2076 - 1) <> $2075
#error Assertion failed: sub_c2076 - 1 == $2075
#endif
#if (sub_c2079 - 1) <> $2078
#error Assertion failed: sub_c2079 - 1 == $2078
#endif
#if (sub_c207c - 1) <> $207b
#error Assertion failed: sub_c207c - 1 == $207b
#endif

// Label references by decreasing frequency:
//     c2018:        1
//     c201a:        1
//     c2023:        1
//     c203d:        1
//     c204e:        1
//     l0070:        1
//     l0071:        1
//     l0072:        1
//     l2058:        1
//     l205c:        1
//     l205d:        1
//     l2062:        1
//     l2063:        1
//     loop_c2032:   1
//     sub_c2010:    1
//     sub_c201c:    1
//     sub_c202e:    1
//     sub_c2049:    1
//     sub_c2050:    1
//     sub_c2056:    1

// Automatically generated labels:
//     c2018
//     c201a
//     c2023
//     c203d
//     c204e
//     l0070
//     l0071
//     l0072
//     l2058
//     l205c
//     l205d
//     l2062
//     l2063
//     loop_c2032
//     sub_c2010
//     sub_c201c
//     sub_c202e
//     sub_c2049
//     sub_c2050
//     sub_c2056
//     sub_c206a
//     sub_c206d
//     sub_c2070
//     sub_c2073
//     sub_c2076
//     sub_c2079
//     sub_c207c

// Stats:
//
//     Total size (Code + Data) = 127 bytes
//     Code                     = 109 bytes (86%)
//     Data                     = 18 bytes (14%)
//
//     Number of instructions   = 63
//     Number of data bytes     = 0 bytes
//     Number of data words     = 14 bytes
//     Number of string bytes   = 4 bytes
//     Number of strings        = 1

