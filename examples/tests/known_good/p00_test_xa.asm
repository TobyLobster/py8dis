// Memory locations
chrout  = $ffd2

// The PRG file's header: the address to load it at
    * = $07ff
    .word $0801

    * = $0801

pydis_start
    .byt $0b, 8, $0a, 0, $9e                                          // 0801: 0b 08 0a... ...
    .asc "2061"                                                       // 0806: 32 30 36... 206
    .byt 0, 0, 0                                                      // 080a: 00 00 00    ...

start
    ldx #0                                                            // 080d: a2 00       ..
// $080f referenced 1 time by $0818
loop_c080f
    lda l081b,x                                                       // 080f: bd 1b 08    ...
    beq return_1                                                      // 0812: f0 06       ..
    jsr chrout                                                        // 0814: 20 d2 ff     ..
    inx                                                               // 0817: e8          .
    bne loop_c080f                                                    // 0818: d0 f5       ..
// $081a referenced 1 time by $0812
return_1
    rts                                                               // 081a: 60          `

// $081b referenced 1 time by $080f
l081b
    .asc "HELLO"                                                      // 081b: 48 45 4c... HEL
    .byt $0d, 0                                                       // 0820: 0d 00       ..
pydis_end


// Label references by decreasing frequency:
//     chrout:       1
//     l081b:        1
//     loop_c080f:   1
//     return_1:     1

// Automatically generated labels:
//     l081b
//     loop_c080f
//     return_1

// Stats:
//
//     Total size (Code + Data) = 33 bytes
//     Code                     = 14 bytes (42%)
//     Data                     = 19 bytes (58%)
//
//     Number of instructions   = 7
//     Number of data bytes     = 10 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 9 bytes
//     Number of strings        = 2

