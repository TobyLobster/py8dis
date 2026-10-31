// Memory locations

// Zero page ($0000-$00ff)
irq_vector              = $0090
keyboard_buffer_length  = $009e
reverse_flag            = $009f

// Screen memory ($8000-$87cf)
screen_memory   = $8000

// BASIC ROM ($b000-$dfff)
basic_print_string  = $bb1d
basic_print_number  = $cf83

// Screen editor ROM ($e000-$e7ff)
kernal_irq_handler  = $e455

// PIA 1 ($e810-$e813)
pia1_port_a = $e810
pia1_port_b = $e812

// VIA ($e840-$e84f)
via_peripheral_control  = $e84c

// CRTC ($e880-$e881)
crtc_address = $e880
crtc_data   = $e881

// Kernal entry points ($ffc0-$fff9)
CLRCHN  = $ffcc
CHROUT  = $ffd2
STOP    = $ffe1
GETIN   = $ffe4

// The PRG file's header: the address to load it at
    * = $03ff
    .word $0401

    * = $0401

// 10 SYS1056
pydis_start
basic_line_10
    .word basic_line_20                                               // 0401: 0b 04       ..
    .word 10                                                          // 0403: 0a 00       ..
    .byt $9e                                                          // 0405: 9e          .
    .byt $31, $30, $35, $36 // petscii "1056"                         // 0406: 31 30 35... 105
    .byt 0                                                            // 040a: 00          .
// 20 CATALOG
basic_line_20
    .word basic_end                                                   // 040b: 11 04       ..
    .word 20                                                          // 040d: 14 00       ..
    .byt $d7                                                          // 040f: d7          W
    .byt 0                                                            // 0410: 00          .
basic_end
    .word 0                                                           // 0411: 00 00       ..
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                        // 0413: 00 00 00... ...

sys_entry
    lda #$93                                                          // 0420: a9 93       .. // A=character to output
    jsr CHROUT                                                        // 0422: 20 d2 ff     R. // Output $93 (clear screen)
    lda #<l0478                                                       // 0425: a9 78       .. // A=string address (low byte)
    ldy #>l0478                                                       // 0427: a0 04       .. // Y=string address (high byte)
    jsr basic_print_string                                            // 0429: 20 1d bb     .. // Print the zero-terminated string at A/Y
    lda #4                                                            // 042c: a9 04       .. // A=number to print (high byte)
    ldx #$d2 // 'R'                                                   // 042e: a2 d2       .R // X=number to print (low byte)
    jsr basic_print_number                                            // 0430: 20 83 cf     .O // Print the 16-bit number in A/X
    sei                                                               // 0433: 78          .

    // Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 // 0434: a9 72       ..
    sta irq_vector                                                    // 0436: 85 90       ..
    lda #>irq_handler                                                 // 0438: a9 04       ..
    sta irq_vector+1                                                  // 043a: 85 91       ..

    cli                                                               // 043c: 58          x
    lda #$0e                                                          // 043d: a9 0e       ..
    sta via_peripheral_control                                        // 043f: 8d 4c e8    .l.
    lda #$0c                                                          // 0442: a9 0c       ..
    sta crtc_address                                                  // 0444: 8d 80 e8    ...
    lda #$10                                                          // 0447: a9 10       ..
    sta crtc_data                                                     // 0449: 8d 81 e8    ...
    lda #1                                                            // 044c: a9 01       ..
    sta reverse_flag                                                  // 044e: 85 9f       ..
    lda #$61                                                          // 0450: a9 61       ..
    sta screen_memory                                                 // 0452: 8d 00 80    ...
    lda #0                                                            // 0455: a9 00       ..
    sta keyboard_buffer_length                                        // 0457: 85 9e       ..
// $0459 referenced 1 time by $0461
loop_c0459
    jsr STOP                                                          // 0459: 20 e1 ff     .. // Check the STOP key (Z set if it's pressed)
    beq c0466                                                         // 045c: f0 08       ..
    jsr GETIN                                                         // 045e: 20 e4 ff     .. // Get a character from the keyboard buffer (0 if there's none)
    beq loop_c0459                                                    // 0461: f0 f6       ..
    jsr CHROUT                                                        // 0463: 20 d2 ff     R. // Output a character
// $0466 referenced 1 time by $045c
c0466
    jsr CLRCHN                                                        // 0466: 20 cc ff     L. // Restore the default input and output (keyboard and screen)
    lda #9                                                            // 0469: a9 09       ..
    sta pia1_port_a                                                   // 046b: 8d 10 e8    ...
    lda pia1_port_b                                                   // 046e: ad 12 e8    ...
    rts                                                               // 0471: 60          .

irq_handler
    inc screen_memory+39                                              // 0472: ee 27 80    .'.
    jmp kernal_irq_handler                                            // 0475: 4c 55 e4    lu. // The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

l0478
    .byt $48, $45, $4c, $4c, $4f, $2c, $20, $50 // petscii "hello, p" // 0478: 48 45 4c... hel
    .byt $45, $54, $0d, 0 // petscii "et", $0d, $00                   // 0480: 45 54 0d... et.
pydis_end

#if ((irq_handler) & $ff) <> $72
#error Assertion failed: <irq_handler == $72
#endif
#if ((l0478) & $ff) <> $78
#error Assertion failed: <l0478 == $78
#endif
#if (((irq_handler) >> 8) & $ff) <> $04
#error Assertion failed: >irq_handler == $04
#endif
#if (((l0478) >> 8) & $ff) <> $04
#error Assertion failed: >l0478 == $04
#endif
#if (basic_end) <> $0411
#error Assertion failed: basic_end == $0411
#endif
#if (basic_line_20) <> $040b
#error Assertion failed: basic_line_20 == $040b
#endif

// Label references by decreasing frequency:
//     CHROUT:                   2
//     CLRCHN:                   1
//     GETIN:                    1
//     STOP:                     1
//     basic_print_number:       1
//     basic_print_string:       1
//     c0466:                    1
//     crtc_address:             1
//     crtc_data:                1
//     irq_vector:               1
//     kernal_irq_handler:       1
//     keyboard_buffer_length:   1
//     loop_c0459:               1
//     pia1_port_a:              1
//     pia1_port_b:              1
//     reverse_flag:             1
//     screen_memory:            1
//     via_peripheral_control:   1

// Automatically generated labels:
//     c0466
//     l0478
//     loop_c0459

// Stats:
//
//     Total size (Code + Data) = 131 bytes
//     Code                     = 88 bytes (67%)
//     Data                     = 43 bytes (33%)
//
//     Number of instructions   = 38
//     Number of data bytes     = 17 bytes
//     Number of data words     = 10 bytes
//     Number of string bytes   = 16 bytes
//     Number of strings        = 2

