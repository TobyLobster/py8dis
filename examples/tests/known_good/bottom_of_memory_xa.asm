// Memory locations
lfff2   = $fff2

    * = $0000

pydis_start
start
    nop                                                               // 0000: ea          .
    nop                                                               // 0001: ea          .
    bmi lfff2                                                         // 0002: 30 ee       0.
    rts                                                               // 0004: 60          `

pydis_end


// Label references by decreasing frequency:
//     lfff2:   1

// Automatically generated labels:
//     lfff2

// Stats:
//
//     Total size (Code + Data) = 5 bytes
//     Code                     = 5 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 4
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

