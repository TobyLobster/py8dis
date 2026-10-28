// Constants
colour_black    = 0

// Memory locations

// Zero page ($0000-$00ff)
l00fb   = $00fb
l00fc   = $00fc

// OS workspace ($0200-$03ff)
basic_error_vector  = $0300

// BASIC ROM ($4000-$afff)
l4000   = $4000

// VIC-II ($d000-$d3ff)
vic_interrupt_status    = $d019
vic_border_colour       = $d020
vic_background_colour_0 = $d021

// MMU ($d500-$d5ff)
mmu_configuration_io = $d500

// MMU ($ff00-$ff04)
mmu_configuration       = $ff00
mmu_load_configuration_a = $ff01

// Kernal entry points ($ff47-$fff9)
chrout  = $ffd2

// Other banks
l1000   = $1000
ld000   = $d000
ld019   = $d019
ld020   = $d020
le000   = $e000
lff7d   = $ff7d
lffd2   = $ffd2

// The PRG file's header: the address to load it at
    * = $1bff
    .word $1c01

    * = $1c01

// 10 SYS7181
pydis_start
basic_line_10
    .word basic_end                                                   // 1c01: 0b 1c       ..
    .word 10                                                          // 1c03: 0a 00       ..
    .byt $9e                                                          // 1c05: 9e          .
    .byt $37, $31, $38, $31 // petscii "7181"                         // 1c06: 37 31 38... 718
    .byt 0                                                            // 1c0a: 00          .
basic_end
    .word 0                                                           // 1c0b: 00 00       ..

sys_entry
    lda #colour_black                                                 // 1c0d: a9 00       ..
    sta mmu_configuration                                             // 1c0f: 8d 00 ff    ... // Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    sta vic_border_colour                                             // 1c12: 8d 20 d0    . P
    lda #$3e // '>'                                                   // 1c15: a9 3e       .>
    sta mmu_configuration                                             // 1c17: 8d 00 ff    ... // Set the MMU to RAM 0, I/O
    sta vic_background_colour_0                                       // 1c1a: 8d 21 d0    .!P
    lda le000                                                         // 1c1d: ad 00 e0    ...
    sta l00fb                                                         // 1c20: 85 fb       ..
    lda #$3f // '?'                                                   // 1c22: a9 3f       .?
    sta mmu_configuration                                             // 1c24: 8d 00 ff    ... // Set the MMU to bank 0 (RAM 0 only)
    lda ld020                                                         // 1c27: ad 20 d0    . P
    sta l00fc                                                         // 1c2a: 85 fc       ..
    lda #$41 // 'a'                                                   // 1c2c: a9 41       .a
    jsr lffd2                                                         // 1c2e: 20 d2 ff     R.
    lda #0                                                            // 1c31: a9 00       ..
    sta mmu_configuration                                             // 1c33: 8d 00 ff    ... // Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    ldx #$7f                                                          // 1c36: a2 7f       ..
    stx mmu_configuration_io                                          // 1c38: 8e 00 d5    ..U // Set the MMU to bank 1 (RAM 1 only)
    lda l1000                                                         // 1c3b: ad 00 10    ...
    sta basic_error_vector                                            // 1c3e: 8d 00 03    ...
    sta mmu_load_configuration_a                                      // 1c41: 8d 01 ff    ... // Set the MMU to preconfiguration A (as set at $d501)
    lda vic_border_colour                                             // 1c44: ad 20 d0    . P
    lda #0                                                            // 1c47: a9 00       ..
    sta mmu_configuration                                             // 1c49: 8d 00 ff    ... // Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    jsr sub_c1c5d                                                     // 1c4c: 20 5d 1c     ].
    lda vic_border_colour                                             // 1c4f: ad 20 d0    . P
    lda #$41 // 'a'                                                   // 1c52: a9 41       .a // A=character to output
    jsr chrout                                                        // 1c54: 20 d2 ff     R. // Output 'a'
    lda #1                                                            // 1c57: a9 01       ..
    sta vic_interrupt_status                                          // 1c59: 8d 19 d0    ..P // Acknowledge the VIC-II's raster interrupt
    rts                                                               // 1c5c: 60          .

// $1c5d referenced 1 time by $1c4c
sub_c1c5d
    ldx #0                                                            // 1c5d: a2 00       ..
// $1c5f referenced 1 time by $1c66
loop_c1c5f
    lda ld000,x                                                       // 1c5f: bd 00 d0    ..P
    sta l4000,x                                                       // 1c62: 9d 00 40    ..@
    inx                                                               // 1c65: e8          .
    bne loop_c1c5f                                                    // 1c66: d0 f7       P.
    lda #1                                                            // 1c68: a9 01       ..
    sta ld020                                                         // 1c6a: 8d 20 d0    . P
    sta ld019                                                         // 1c6d: 8d 19 d0    ..P
    jsr lff7d                                                         // 1c70: 20 7d ff     ..
    rts                                                               // 1c73: 60          .

pydis_end

#if (basic_end) <> $1c0b
#error Assertion failed: basic_end == $1c0b
#endif

// Label references by decreasing frequency:
//     ld020:                      5
//     mmu_configuration:          5
//     vic_border_colour:          5
//     chrout:                     2
//     ld019:                      2
//     lffd2:                      2
//     vic_interrupt_status:       2
//     basic_error_vector:         1
//     l00fb:                      1
//     l00fc:                      1
//     l1000:                      1
//     l4000:                      1
//     ld000:                      1
//     le000:                      1
//     lff7d:                      1
//     loop_c1c5f:                 1
//     mmu_configuration_io:       1
//     mmu_load_configuration_a:   1
//     sub_c1c5d:                  1
//     vic_background_colour_0:    1

// Automatically generated labels:
//     l00fb
//     l00fc
//     l4000
//     loop_c1c5f
//     sub_c1c5d

// Stats:
//
//     Total size (Code + Data) = 115 bytes
//     Code                     = 103 bytes (90%)
//     Data                     = 12 bytes (10%)
//
//     Number of instructions   = 41
//     Number of data bytes     = 2 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 4 bytes
//     Number of strings        = 1

