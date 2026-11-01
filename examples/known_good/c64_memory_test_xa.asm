// Constants
colour_black    = 0
colour_white    = 1

// Memory locations

// 6510 I/O port ($0000-$0001)
cpu_port = $0001

// BASIC program area ($0800-$9fff)
l4000   = $4000

// VIC-II ($d000-$d3ff)
vic_border_colour       = $d020
vic_background_colour_0 = $d021

// Kernal ROM ($e000-$ff80)
le010   = $e010

// Kernal entry points ($ff81-$fff9)
CHROUT  = $ffd2

// 6502 vectors ($fffa-$ffff)
hardware_irq_vector = $fffe

// Other memory configurations
la000   = $a000
ld000   = $d000
ld020   = $d020
le000   = $e000
lffd2   = $ffd2

// The PRG file's header: the address to load it at
    * = $07ff
    .word $0801

    * = $0801

// 10 SYS2061
pydis_start
basic_line_10
    .word basic_end                                                   // 0801: 0b 08       ..
    .word 10                                                          // 0803: 0a 00       ..
    .byt $9e                                                          // 0805: 9e          .
    .byt $32, $30, $36, $31 // petscii "2061"                         // 0806: 32 30 36... 206
    .byt 0                                                            // 080a: 00          .
basic_end
    .word 0                                                           // 080b: 00 00       ..

sys_entry
    sei                                                               // 080d: 78          .
    lda #$35 // '5'                                                   // 080e: a9 35       .5
    sta cpu_port                                                      // 0810: 85 01       .. // Set the memory configuration to RAM, I/O ($35)
    lda #colour_black                                                 // 0812: a9 00       ..
    sta vic_border_colour                                             // 0814: 8d 20 d0    . P
    lda le000                                                         // 0817: ad 00 e0    ...
    sta la000                                                         // 081a: 8d 00 a0    ...
    jsr lffd2                                                         // 081d: 20 d2 ff     R.
    dec cpu_port                                                      // 0820: c6 01       F. // Set the memory configuration to RAM only ($34)
    ldx #0                                                            // 0822: a2 00       ..
// $0824 referenced 1 time by $082b
loop_c0824
    lda ld000,x                                                       // 0824: bd 00 d0    ..P
    sta l4000,x                                                       // 0827: 9d 00 40    ..@
    inx                                                               // 082a: e8          .
    bne loop_c0824                                                    // 082b: d0 f7       P.
    jsr sub_c0853                                                     // 082d: 20 53 08     s.
    inc cpu_port                                                      // 0830: e6 01       .. // Set the memory configuration to RAM, I/O ($35)
    lda #colour_white                                                 // 0832: a9 01       ..
    sta vic_background_colour_0                                       // 0834: 8d 21 d0    .!P
    lda cpu_port                                                      // 0837: a5 01       ..
    and #$f8                                                          // 0839: 29 f8       ).
    ora #7                                                            // 083b: 09 07       ..
    sta cpu_port                                                      // 083d: 85 01       .. // Set the memory configuration to the usual one (RAM, BASIC ROM, Kernal ROM, I/O) ($37)
    lda #$61                                                          // 083f: a9 61       .. // A=character to output
    jsr CHROUT                                                        // 0841: 20 d2 ff     R. // Output $61
    jsr sub_c085a                                                     // 0844: 20 5a 08     z.
    lda le000                                                         // 0847: ad 00 e0    ... // Redundant instruction?
    lda #$37 // '7'                                                   // 084a: a9 37       .7
    sta cpu_port                                                      // 084c: 85 01       .. // Set the memory configuration to the usual one (RAM, BASIC ROM, Kernal ROM, I/O) ($37)
    jsr sub_c0863                                                     // 084e: 20 63 08     ..
    cli                                                               // 0851: 58          x
    rts                                                               // 0852: 60          .

// $0853 referenced 1 time by $082d
sub_c0853
    lda ld020                                                         // 0853: ad 20 d0    . P
    sta le000                                                         // 0856: 8d 00 e0    ...
    rts                                                               // 0859: 60          .

// $085a referenced 1 time by $0844
sub_c085a
    lda #$35 // '5'                                                   // 085a: a9 35       .5
    sta cpu_port                                                      // 085c: 85 01       .. // Set the memory configuration to RAM, I/O ($35)
    rts                                                               // 085e: 60          .

kernal_out_routine_entry
    lda le010                                                         // 085f: ad 10 e0    ...
    rts                                                               // 0862: 60          .

// $0863 referenced 1 time by $084e
sub_c0863
    lda hardware_irq_vector                                           // 0863: ad fe ff    ...
    rts                                                               // 0866: 60          .

pydis_end

#if (basic_end) <> $080b
#error Assertion failed: basic_end == $080b
#endif

// Label references by decreasing frequency:
//     cpu_port:                  7
//     le000:                     3
//     CHROUT:                    2
//     ld020:                     2
//     lffd2:                     2
//     vic_border_colour:         2
//     hardware_irq_vector:       1
//     l4000:                     1
//     la000:                     1
//     ld000:                     1
//     le010:                     1
//     loop_c0824:                1
//     sub_c0853:                 1
//     sub_c085a:                 1
//     sub_c0863:                 1
//     vic_background_colour_0:   1

// Automatically generated labels:
//     l4000
//     le010
//     loop_c0824
//     sub_c0853
//     sub_c085a
//     sub_c0863

// Stats:
//
//     Total size (Code + Data) = 102 bytes
//     Code                     = 90 bytes (88%)
//     Data                     = 12 bytes (12%)
//
//     Number of instructions   = 41
//     Number of data bytes     = 2 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 4 bytes
//     Number of strings        = 1

