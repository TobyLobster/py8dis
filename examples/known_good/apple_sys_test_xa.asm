// Memory locations
lfded   = $fded

    * = $2000

// ProDOS runs a SYS file from here
pydis_start
    ldx #0                                                            // 2000: a2 00       ..
// $2002 referenced 1 time by $200b
loop_c2002
    lda l200e,x                                                       // 2002: bd 0e 20    ..
    beq return_1                                                      // 2005: f0 06       ..
    jsr lfded                                                         // 2007: 20 ed fd     ..
    inx                                                               // 200a: e8          .
    bne loop_c2002                                                    // 200b: d0 f5       ..
// $200d referenced 1 time by $2005
return_1
    rts                                                               // 200d: 60          `

// $200e referenced 1 time by $2002
l200e
    .byt $c8, $c5, $cc, $cc, $cf, $8d, 0                              // 200e: c8 c5 cc... ...
pydis_end


// Label references by decreasing frequency:
//     l200e:        1
//     lfded:        1
//     loop_c2002:   1
//     return_1:     1

// Automatically generated labels:
//     l200e
//     lfded
//     loop_c2002
//     return_1

// Stats:
//
//     Total size (Code + Data) = 21 bytes
//     Code                     = 14 bytes (67%)
//     Data                     = 7 bytes (33%)
//
//     Number of instructions   = 7
//     Number of data bytes     = 7 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

