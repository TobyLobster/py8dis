// Memory locations

// Zero page ($0000-$00ff)
irq_vector              = $0090
keyboard_buffer_length  = $009e
reverse_flag            = $009f

// Screen memory ($8000-$83e7)
screen_memory   = $8000

// BASIC ROM ($c000-$dfff)
basic_print_string  = $ca1c
basic_print_number  = $dcd9

// Screen editor ROM ($e000-$e7ff)
kernal_irq_handler  = $e62e

// PIA 1 ($e810-$e813)
pia1_port_a = $e810
pia1_port_b = $e812

// VIA ($e840-$e84f)
via_peripheral_control  = $e84c

// Kernal entry points ($ffc0-$fff9)
clrchn  = $ffcc
chrout  = $ffd2
stop    = $ffe1
getin   = $ffe4

// The PRG file's header: the address to load it at
    * = $03ff
    .word $0401

    * = $0401

// 10 SYS1056
pydis_start
basic_line_10
    .word basic_end                                                   // 0401: 0b 04       ..
    .word 10                                                          // 0403: 0a 00       ..
    .byt $9e                                                          // 0405: 9e          .
    .byt $31, $30, $35, $36 // petscii "1056"                         // 0406: 31 30 35... 105
    .byt 0                                                            // 040a: 00          .
basic_end
    .word 0                                                           // 040b: 00 00       ..
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0      // 040d: 00 00 00... ...

sys_entry
    lda #$93                                                          // 0420: a9 93       .. // A=character to output
    jsr chrout                                                        // 0422: 20 d2 ff     R. // Output $93 (clear screen)
    lda #<l046e                                                       // 0425: a9 6e       .. // A=string address (low byte)
    ldy #>l046e                                                       // 0427: a0 04       .. // Y=string address (high byte)
    jsr basic_print_string                                            // 0429: 20 1c ca     .J // Print the zero-terminated string at A/Y
    lda #4                                                            // 042c: a9 04       .. // A=number to print (high byte)
    ldx #$d2 // 'R'                                                   // 042e: a2 d2       .R // X=number to print (low byte)
    jsr basic_print_number                                            // 0430: 20 d9 dc     Y. // Print the 16-bit number in A/X
    sei                                                               // 0433: 78          .

    // Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 // 0434: a9 68       ..
    sta irq_vector                                                    // 0436: 85 90       ..
    lda #>irq_handler                                                 // 0438: a9 04       ..
    sta irq_vector+1                                                  // 043a: 85 91       ..

    cli                                                               // 043c: 58          x
    lda #$0e                                                          // 043d: a9 0e       ..
    sta via_peripheral_control                                        // 043f: 8d 4c e8    .l.
    lda #1                                                            // 0442: a9 01       ..
    sta reverse_flag                                                  // 0444: 85 9f       ..
    lda #$61                                                          // 0446: a9 61       ..
    sta screen_memory                                                 // 0448: 8d 00 80    ...
    lda #0                                                            // 044b: a9 00       ..
    sta keyboard_buffer_length                                        // 044d: 85 9e       ..
// $044f referenced 1 time by $0457
loop_c044f
    jsr stop                                                          // 044f: 20 e1 ff     .. // Check the STOP key (Z set if it's pressed)
    beq c045c                                                         // 0452: f0 08       ..
    jsr getin                                                         // 0454: 20 e4 ff     .. // Get a character from the keyboard buffer (0 if there's none)
    beq loop_c044f                                                    // 0457: f0 f6       ..
    jsr chrout                                                        // 0459: 20 d2 ff     R. // Output a character
// $045c referenced 1 time by $0452
c045c
    jsr clrchn                                                        // 045c: 20 cc ff     L. // Restore the default input and output (keyboard and screen)
    lda #9                                                            // 045f: a9 09       ..
    sta pia1_port_a                                                   // 0461: 8d 10 e8    ...
    lda pia1_port_b                                                   // 0464: ad 12 e8    ...
    rts                                                               // 0467: 60          .

irq_handler
    inc screen_memory+39                                              // 0468: ee 27 80    .'.
    jmp kernal_irq_handler                                            // 046b: 4c 2e e6    l.. // The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

l046e
    .byt $48, $45, $4c, $4c, $4f, $2c, $20, $50 // petscii "hello, p" // 046e: 48 45 4c... hel
    .byt $45, $54, $0d, 0 // petscii "et", $0d, $00                   // 0476: 45 54 0d... et.
pydis_end

#if ((irq_handler) & $ff) <> $68
#error Assertion failed: <irq_handler == $68
#endif
#if ((l046e) & $ff) <> $6e
#error Assertion failed: <l046e == $6e
#endif
#if (((irq_handler) >> 8) & $ff) <> $04
#error Assertion failed: >irq_handler == $04
#endif
#if (((l046e) >> 8) & $ff) <> $04
#error Assertion failed: >l046e == $04
#endif
#if (basic_end) <> $040b
#error Assertion failed: basic_end == $040b
#endif

// Label references by decreasing frequency:
//     chrout:                   2
//     basic_print_number:       1
//     basic_print_string:       1
//     c045c:                    1
//     clrchn:                   1
//     getin:                    1
//     irq_vector:               1
//     kernal_irq_handler:       1
//     keyboard_buffer_length:   1
//     loop_c044f:               1
//     pia1_port_a:              1
//     pia1_port_b:              1
//     reverse_flag:             1
//     screen_memory:            1
//     stop:                     1
//     via_peripheral_control:   1

// Automatically generated labels:
//     c045c
//     l046e
//     loop_c044f

// Stats:
//
//     Total size (Code + Data) = 121 bytes
//     Code                     = 78 bytes (64%)
//     Data                     = 43 bytes (36%)
//
//     Number of instructions   = 34
//     Number of data bytes     = 21 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 16 bytes
//     Number of strings        = 2

