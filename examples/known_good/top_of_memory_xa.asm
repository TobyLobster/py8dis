// Memory locations

// Zero page ($0000-$00ff)
l0020   = $0020

// Other
l412c   = $412c

    * = $ffe0

pydis_start
start
    ldx #$80                                                          // ffe0: a2 80       ..
    bmi l0020                                                         // ffe2: 30 3c       0< // ALWAYS branch

    jmp cfffd                                                         // ffe4: 4c fd ff    L..

    .asc "THE TOP OF MEMORY"                                          // ffe7: 54 48 45... THE
    .byt 0, 0, 0, 0, 0                                                // fff8: 00 00 00... ...

// $fffd referenced 1 time by $ffe4
cfffd
    bit l412c                                                         // fffd: 2c 2c 41    ,,A
pydis_end


// Label references by decreasing frequency:
//     cfffd:   1
//     l0020:   1
//     l412c:   1

// Automatically generated labels:
//     cfffd
//     l0020
//     l412c

// Stats:
//
//     Total size (Code + Data) = 32 bytes
//     Code                     = 10 bytes (31%)
//     Data                     = 22 bytes (69%)
//
//     Number of instructions   = 4
//     Number of data bytes     = 5 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 17 bytes
//     Number of strings        = 1

