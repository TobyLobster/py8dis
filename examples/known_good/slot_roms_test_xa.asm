// Constants
SP_READBLOCK    = $01

// Memory locations

// Stack ($0100-$01ff)
l0101   = $0101

// Text and lo-res page 1 ($0400-$07ff)
l047c   = $047c
MSLOT   = $07f8

// Text and lo-res page 2 ($0800-$0bff)
data_buffer = $0800
l0801       = $0801

// Slot I/O ($c090-$c0ff)
slot_2_io   = $c0a0
slot_3_io   = $c0b0
slot_4_io   = $c0c0
slot_5_io   = $c0d0

// Monitor ROM ($f800-$ffff)
COUT    = $fded
IORTS   = $ff58

// ProDOS driver's parameters
driver_command      = $0042
driver_unit         = $0043
driver_buffer       = $0044
driver_buffer_high  = $0045
driver_block        = $0046
driver_block_high   = $0047

// The card's I/O (indexed by the slot times 16)
card_io_9   = $c089
card_io_14  = $c08e

    * = $c200

// Slot 2's ROM: PR#2, IN#2 and booting from slot 2 start here
// ID bytes $38, $18 and $01 at $c205, $c207 and $c20b: the Pascal 1.1 firmware
// protocol
pydis_start
slot_2_entry
    bit IORTS                                                         // c200: 2c 58 ff    ...
    bvs cc220                                                         // c203: 70 1b       ..
// BASIC's input entry point (whose SEC is the ID byte $38)
basic_input
    sec                                                               // c205: 38          .
// overlapping: bcc cc220                                             // c206: 90 18       ..
    .byt $90                                                          // c206: 90          .

// BASIC's output entry point (whose CLC is the ID byte $18)
basic_output
    clc                                                               // c207: 18          .
    jmp cc220                                                         // c208: 4c 20 c2    ..B

    .byt 1                                                            // c20b: 01          .  // Pascal 1.1's generic signature
    .byt $31                                                          // c20c: 31          .  // Device signature: class 3 (serial or communications), ID 1
    .byt <pascal_init                                                 // c20d: 11          .  // Offset of pascal_init
    .byt <pascal_read                                                 // c20e: 14          .  // Offset of pascal_read
    .byt <pascal_write                                                // c20f: 1a          .  // Offset of pascal_write
    .byt <pascal_status                                               // c210: 26          .  // Offset of pascal_status

// Pascal 1.1 INIT routine
pascal_init
    ldx #0                                                            // c211: a2 00       ".
    rts                                                               // c213: 60          .

// Pascal 1.1 READ routine
pascal_read
    lda slot_2_io+8                                                   // c214: ad a8 c0    -(@
    ldx #0                                                            // c217: a2 00       ".
    rts                                                               // c219: 60          .

// Pascal 1.1 WRITE routine
pascal_write
    sta slot_2_io+8                                                   // c21a: 8d a8 c0    .(@
    ldx #0                                                            // c21d: a2 00       ".
    rts                                                               // c21f: 60          .

// $c220 referenced 2 times by $c203, $c208
cc220
    ldx #$20                                                          // c220: a2 20       ".
    lda card_io_9,x                                                   // c222: bd 89 c0    =.@
    rts                                                               // c225: 60          .

// Pascal 1.1 STATUS routine
pascal_status
    lda slot_2_io+9                                                   // c226: ad a9 c0    -)@
    and #$10                                                          // c229: 29 10       ..
    ldx #0                                                            // c22b: a2 00       ".
    rts                                                               // c22d: 60          .

    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c22e: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c242: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c256: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c26a: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c27e: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c292: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c2a6: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c2ba: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c2ce: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c2e2: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                                 // c2f6: 00 00 00... ...

// Slot 3's ROM: PR#3, IN#3 and booting from slot 3 start here
// (No ID bytes of a ProDOS block device or a Pascal 1.1 card)
slot_3_entry
    lda #$8d                                                          // c300: a9 8d       ).
    jsr COUT                                                          // c302: 20 ed fd    .m} // Print a carriage return
    lda slot_3_io                                                     // c305: ad b0 c0    -0@
    rts                                                               // c308: 60          .

    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c309: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c31d: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c331: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c345: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c359: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c36d: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c381: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c395: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c3a9: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c3bd: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c3d1: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c3e5: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0                                          // c3f9: 00 00 00... ...

// Slot 4's ROM: PR#4, IN#4 and booting from slot 4 start here
// ID bytes $38, $18 and $01 at $c405, $c407 and $c40b: the Pascal 1.1 firmware
// protocol
slot_4_entry
    bit IORTS                                                         // c400: 2c 58 ff    ...
    bvs return_1                                                      // c403: 70 1b       ..
// BASIC's input entry point (whose SEC is the ID byte $38)
basic_input_2
    sec                                                               // c405: 38          .
// overlapping: bcc return_1                                          // c406: 90 18       ..
    .byt $90                                                          // c406: 90          .

// BASIC's output entry point (whose CLC is the ID byte $18)
basic_output_2
    clc                                                               // c407: 18          .
    jmp return_1                                                      // c408: 4c 20 c4    ..D

    .byt 1                                                            // c40b: 01          .  // Pascal 1.1's generic signature
    .byt $20                                                          // c40c: 20          .  // Device signature: class 2 (mouse), ID 0
    .byt <pascal_init_2                                               // c40d: 1a          .  // Offset of pascal_init
    .byt <pascal_init_2                                               // c40e: 1a          .  // Offset of pascal_read
    .byt <pascal_init_2                                               // c40f: 1a          .  // Offset of pascal_write
    .byt <pascal_status_2                                             // c410: 21          .  // Offset of pascal_status
    .byt 0                                                            // c411: 00          .
    .byt <SETMOUSE                                                    // c412: 25          .  // Offset of SETMOUSE
    .byt <SERVEMOUSE                                                  // c413: 2a          .  // Offset of SERVEMOUSE
    .byt <READMOUSE                                                   // c414: 2f          .  // Offset of READMOUSE
    .byt <CLEARMOUSE                                                  // c415: 37          .  // Offset of CLEARMOUSE
    .byt <CLEARMOUSE                                                  // c416: 37          .  // Offset of POSMOUSE
    .byt <CLEARMOUSE                                                  // c417: 37          .  // Offset of CLAMPMOUSE
    .byt <CLEARMOUSE                                                  // c418: 37          .  // Offset of HOMEMOUSE
    .byt <INITMOUSE                                                   // c419: 39          .  // Offset of INITMOUSE

// Pascal 1.1 INIT routine
// Pascal 1.1 READ routine
// Pascal 1.1 WRITE routine
pascal_init_2
    lda #0                                                            // c41a: a9 00       ).
    ldx #3                                                            // c41c: a2 03       ".
    sec                                                               // c41e: 38          .
    rts                                                               // c41f: 60          .

// $c420 referenced 2 times by $c403, $c408
return_1
    rts                                                               // c420: 60          .

// Pascal 1.1 STATUS routine
pascal_status_2
    ldx #0                                                            // c421: a2 00       ".
    clc                                                               // c423: 18          .
    rts                                                               // c424: 60          .

// Mouse: set the mode
SETMOUSE
    sta slot_4_io                                                     // c425: 8d c0 c0    .@@
    clc                                                               // c428: 18          .
    rts                                                               // c429: 60          .

// Mouse: service an interrupt
SERVEMOUSE
    lda slot_4_io+1                                                   // c42a: ad c1 c0    -A@
    clc                                                               // c42d: 18          .
    rts                                                               // c42e: 60          .

// Mouse: read the position and buttons
READMOUSE
    lda slot_4_io+2                                                   // c42f: ad c2 c0    -B@
    sta l047c                                                         // c432: 8d 7c 04    ...
    clc                                                               // c435: 18          .
    rts                                                               // c436: 60          .

// Mouse: set the position to 0
// Mouse: set the position
// Mouse: set the bounds
// Mouse: move to the top left of the bounds
CLEARMOUSE
    clc                                                               // c437: 18          .
    rts                                                               // c438: 60          .

// Mouse: reset the bounds, and set the position to 0
INITMOUSE
    sta slot_4_io+3                                                   // c439: 8d c3 c0    .C@
    clc                                                               // c43c: 18          .
    rts                                                               // c43d: 60          .

    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c43e: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c452: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c466: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c47a: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c48e: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c4a2: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c4b6: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c4ca: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c4de: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                     // c4f2: 00 00 00... ...

// Slot 5's ROM: PR#5, IN#5 and booting from slot 5 start here
// ID bytes $20, $00 and $03 at $c501, $c503 and $c505: a ProDOS block device, with
// SmartPort ($00 at $c507)
slot_5_entry
    ldx #$20                                                          // c500: a2 20       ". // Redundant instruction?
    ldx #0                                                            // c502: a2 00       ". // Redundant instruction?
    ldx #3                                                            // c504: a2 03       ". // Redundant instruction?
    ldx #0                                                            // c506: a2 00       ". // Redundant instruction?
    lda #$c5 // 'E'                                                   // c508: a9 c5       )E
    sta MSLOT                                                         // c50a: 8d f8 07    .x.
    ldx #$50                                                          // c50d: a2 50       ".
    lda card_io_14,x                                                  // c50f: bd 8e c0    =.@
    jsr smartport                                                     // c512: 20 24 c5    ..E // SmartPort: read a block
    .byt SP_READBLOCK                                                 // c515: 01          .
    .word sp_readblock_params                                         // c516: 36 c5       .E

    bcs cc51d                                                         // c518: b0 03       0.
    jmp l0801                                                         // c51a: 4c 01 08    ...

// $c51d referenced 1 time by $c518
cc51d
    lda slot_5_io                                                     // c51d: ad d0 c0    -P@
    rts                                                               // c520: 60          .

// ProDOS's driver for the device (with its parameters at $42-$47)
prodos_driver
    jmp cc52a                                                         // c521: 4c 2a c5    ..E

// SmartPort's dispatcher: a JSR to it is followed by the call number and the address
// of its parameter list
// $c524 referenced 1 time by $c512
smartport
    tsx                                                               // c524: ba          :
    lda l0101,x                                                       // c525: bd 01 01    =..
    clc                                                               // c528: 18          .
    rts                                                               // c529: 60          .

// $c52a referenced 1 time by $c521
cc52a
    lda driver_command                                                // c52a: a5 42       %. // Redundant instruction?
    ldx driver_unit                                                   // c52c: a6 43       &.
    lda (driver_buffer),y                                             // c52e: b1 44       1.
    lda driver_block                                                  // c530: a5 46       %. // Redundant instruction?
    lda #0                                                            // c532: a9 00       ).
    clc                                                               // c534: 18          .
    rts                                                               // c535: 60          .

sp_readblock_params
    .byt 3                                                            // c536: 03          .  // Parameter count
    .byt 1                                                            // c537: 01          .  // Unit number
    .word data_buffer                                                 // c538: 00 08       .. // Data buffer (512 bytes)
    .byt 0, 0, 0                                                      // c53a: 00 00 00    ... // Block number
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c53d: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c551: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c565: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c579: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c58d: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c5a1: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c5b5: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c5c9: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // c5dd: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                              // c5f1: 00 00 00... ...
    .word 0                                                           // c5fc: 00 00       .. // Number of blocks (0: read it with STATUS)
    .byt $bf                                                          // c5fe: bf          ?  // Status: 3 volumes; removable, formats, writes, reads, gives its status
    .byt <prodos_driver                                               // c5ff: 21          .  // The low byte of the driver's address
pydis_end

#if ((CLEARMOUSE) & $ff) <> $37
#error Assertion failed: <CLEARMOUSE == $37
#endif
#if ((INITMOUSE) & $ff) <> $39
#error Assertion failed: <INITMOUSE == $39
#endif
#if ((READMOUSE) & $ff) <> $2f
#error Assertion failed: <READMOUSE == $2f
#endif
#if ((SERVEMOUSE) & $ff) <> $2a
#error Assertion failed: <SERVEMOUSE == $2a
#endif
#if ((SETMOUSE) & $ff) <> $25
#error Assertion failed: <SETMOUSE == $25
#endif
#if ((pascal_init) & $ff) <> $11
#error Assertion failed: <pascal_init == $11
#endif
#if ((pascal_init_2) & $ff) <> $1a
#error Assertion failed: <pascal_init_2 == $1a
#endif
#if ((pascal_read) & $ff) <> $14
#error Assertion failed: <pascal_read == $14
#endif
#if ((pascal_status) & $ff) <> $26
#error Assertion failed: <pascal_status == $26
#endif
#if ((pascal_status_2) & $ff) <> $21
#error Assertion failed: <pascal_status_2 == $21
#endif
#if ((pascal_write) & $ff) <> $1a
#error Assertion failed: <pascal_write == $1a
#endif
#if ((prodos_driver) & $ff) <> $21
#error Assertion failed: <prodos_driver == $21
#endif
#if (data_buffer) <> $0800
#error Assertion failed: data_buffer == $0800
#endif
#if (sp_readblock_params) <> $c536
#error Assertion failed: sp_readblock_params == $c536
#endif

// Label references by decreasing frequency:
//     IORTS:            2
//     cc220:            2
//     return_1:         2
//     COUT:             1
//     MSLOT:            1
//     card_io_14:       1
//     card_io_9:        1
//     cc51d:            1
//     cc52a:            1
//     driver_block:     1
//     driver_buffer:    1
//     driver_command:   1
//     driver_unit:      1
//     l0101:            1
//     l047c:            1
//     l0801:            1
//     slot_3_io:        1
//     slot_4_io:        1
//     slot_5_io:        1
//     smartport:        1

// Automatically generated labels:
//     cc220
//     cc51d
//     cc52a
//     l0101
//     l047c
//     l0801
//     return_1

// Stats:
//
//     Total size (Code + Data) = 1024 bytes
//     Code                     = 145 bytes (14%)
//     Data                     = 879 bytes (86%)
//
//     Number of instructions   = 77
//     Number of data bytes     = 873 bytes
//     Number of data words     = 6 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

