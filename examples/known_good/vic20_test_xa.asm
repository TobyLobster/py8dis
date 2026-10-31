// Constants
colour_red  = 2

// Memory locations

// OS workspace ($0200-$02ff)
text_colour = $0286

// Vectors ($0300-$0333)
irq_vector  = $0314

// Screen memory ($1e00-$1fff)
screen_memory   = $1e00

// VIC ($9000-$900f)
vic_voice3_frequency        = $900c
vic_volume_aux_colour       = $900e
vic_background_border_colour = $900f

// VIA 1 ($9110-$911f)
via1_port_a             = $9111
via1_data_direction_a   = $9113

// VIA 2 ($9120-$912f)
via2_port_b = $9120
via2_port_a = $9121

// Colour RAM ($9600-$97ff)
colour_ram  = $9600

// BASIC ROM ($c000-$dfff)
basic_print_string  = $cb1e
basic_print_number  = $ddcd

// Kernal ROM ($e000-$ff89)
kernal_irq_handler  = $eabf

// Kernal entry points ($ff8a-$fff9)
CHROUT  = $ffd2
GETIN   = $ffe4
PLOT    = $fff0

// The PRG file's header: the address to load it at
    * = $0fff
    .word $1001

    * = $1001

// 10 SYS4109
pydis_start
basic_line_10
    .word basic_end                                                   // 1001: 0b 10       ..
    .word 10                                                          // 1003: 0a 00       ..
    .byt $9e                                                          // 1005: 9e          .
    .byt $34, $31, $30, $39 // petscii "4109"                         // 1006: 34 31 30... 410
    .byt 0                                                            // 100a: 00          .
basic_end
    .word 0                                                           // 100b: 00 00       ..

sys_entry
    sei                                                               // 100d: 78          .

    // Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 // 100e: a9 81       ..
    sta irq_vector                                                    // 1010: 8d 14 03    ...
    lda #>irq_handler                                                 // 1013: a9 10       ..
    sta irq_vector+1                                                  // 1015: 8d 15 03    ...

    cli                                                               // 1018: 58          x
    lda #8                                                            // 1019: a9 08       ..
    sta vic_background_border_colour                                  // 101b: 8d 0f 90    ...
    lda #$0f                                                          // 101e: a9 0f       ..
    sta vic_volume_aux_colour                                         // 1020: 8d 0e 90    ...
    lda #$c8 // 'H'                                                   // 1023: a9 c8       .H
    sta vic_voice3_frequency                                          // 1025: 8d 0c 90    ...
    lda #colour_red                                                   // 1028: a9 02       ..
    sta text_colour                                                   // 102a: 8d 86 02    ...
    lda #$93                                                          // 102d: a9 93       .. // A=character to output
    jsr CHROUT                                                        // 102f: 20 d2 ff     R. // Output $93 (clear screen)
    ldx #0                                                            // 1032: a2 00       ..
// $1034 referenced 1 time by $103d
loop_c1034
    lda l1087,x                                                       // 1034: bd 87 10    ... // A=character to output
    beq c103f                                                         // 1037: f0 06       ..
    jsr CHROUT                                                        // 1039: 20 d2 ff     R. // Output a character
    inx                                                               // 103c: e8          .
    bne loop_c1034                                                    // 103d: d0 f5       P.
// $103f referenced 1 time by $1037
c103f
    clc                                                               // 103f: 18          .
    ldx #$0a                                                          // 1040: a2 0a       .. // X=cursor row
    ldy #5                                                            // 1042: a0 05       .. // Y=cursor column
    jsr PLOT                                                          // 1044: 20 f0 ff     .. // Move the cursor to row 10, column 5
    ldx #$15                                                          // 1047: a2 15       ..
// $1049 referenced 1 time by $1054
loop_c1049
    lda #$51 // 'q'                                                   // 1049: a9 51       .q
    sta screen_memory,x                                               // 104b: 9d 00 1e    ...
    lda #6                                                            // 104e: a9 06       ..
    sta colour_ram,x                                                  // 1050: 9d 00 96    ...
    dex                                                               // 1053: ca          J
    bpl loop_c1049                                                    // 1054: 10 f3       ..
    lda #0                                                            // 1056: a9 00       ..
    sta via1_data_direction_a                                         // 1058: 8d 13 91    ...
    lda via1_port_a                                                   // 105b: ad 11 91    ...
    sta l109e                                                         // 105e: 8d 9e 10    ...
    lda #$7f                                                          // 1061: a9 7f       ..
    sta via2_port_b                                                   // 1063: 8d 20 91    . .
    lda via2_port_a                                                   // 1066: ad 21 91    .!.
    sta l109f                                                         // 1069: 8d 9f 10    ...
    jsr GETIN                                                         // 106c: 20 e4 ff     .. // Get a character from the input channel (from the keyboard, 0 if there's none)
    sta l10a0                                                         // 106f: 8d a0 10    ... // A=character read
    lda #<l108f                                                       // 1072: a9 8f       .. // A=string address (low byte)
    ldy #>l108f                                                       // 1074: a0 10       .. // Y=string address (high byte)
    jsr basic_print_string                                            // 1076: 20 1e cb     .K // Print the zero-terminated string at A/Y
    lda #0                                                            // 1079: a9 00       .. // A=number to print (high byte)
    ldx #$14                                                          // 107b: a2 14       .. // X=number to print (low byte)
    jsr basic_print_number                                            // 107d: 20 cd dd     M. // Print the 16-bit number in A/X
    rts                                                               // 1080: 60          .

irq_handler
    inc vic_background_border_colour                                  // 1081: ee 0f 90    ...
    jmp kernal_irq_handler                                            // 1084: 4c bf ea    l.. // The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

// $1087 referenced 1 time by $1034
l1087
    .byt $56, $49, $43, $2d, $32, $30 // petscii "vic-20"             // 1087: 56 49 43... vic
    .byt $0d, 0                                                       // 108d: 0d 00       ..
l108f
    .byt $54, $48, $45, $20, $41, $4e, $53, $57 // petscii "the answ" // 108f: 54 48 45... the
    .byt $45, $52, $20, $49, $53, $20, 0 // petscii "er is ", $00     // 1097: 45 52 20... er
// $109e referenced 1 time by $105e
l109e
    .byt 0                                                            // 109e: 00          .
// $109f referenced 1 time by $1069
l109f
    .byt 0                                                            // 109f: 00          .
// $10a0 referenced 1 time by $106f
l10a0
    .byt 0                                                            // 10a0: 00          .
pydis_end

#if ((irq_handler) & $ff) <> $81
#error Assertion failed: <irq_handler == $81
#endif
#if ((l108f) & $ff) <> $8f
#error Assertion failed: <l108f == $8f
#endif
#if (((irq_handler) >> 8) & $ff) <> $10
#error Assertion failed: >irq_handler == $10
#endif
#if (((l108f) >> 8) & $ff) <> $10
#error Assertion failed: >l108f == $10
#endif
#if (basic_end) <> $100b
#error Assertion failed: basic_end == $100b
#endif

// Label references by decreasing frequency:
//     CHROUT:                         2
//     vic_background_border_colour:   2
//     GETIN:                          1
//     PLOT:                           1
//     basic_print_number:             1
//     basic_print_string:             1
//     c103f:                          1
//     colour_ram:                     1
//     irq_vector:                     1
//     kernal_irq_handler:             1
//     l1087:                          1
//     l109e:                          1
//     l109f:                          1
//     l10a0:                          1
//     loop_c1034:                     1
//     loop_c1049:                     1
//     screen_memory:                  1
//     text_colour:                    1
//     via1_data_direction_a:          1
//     via1_port_a:                    1
//     via2_port_a:                    1
//     via2_port_b:                    1
//     vic_voice3_frequency:           1
//     vic_volume_aux_colour:          1

// Automatically generated labels:
//     c103f
//     l1087
//     l108f
//     l109e
//     l109f
//     l10a0
//     loop_c1034
//     loop_c1049

// Stats:
//
//     Total size (Code + Data) = 160 bytes
//     Code                     = 122 bytes (76%)
//     Data                     = 38 bytes (24%)
//
//     Number of instructions   = 52
//     Number of data bytes     = 7 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 25 bytes
//     Number of strings        = 3

