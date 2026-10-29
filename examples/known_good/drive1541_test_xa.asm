// Constants
job_bump    = $c0
job_execute = $e0
job_ok      = 1     // OK
job_read    = $80

// Memory locations

// Zero page ($0000-$00ff)
job_queue       = $0000
job_track_sector = $0006
nmi_vector      = $0065

// Buffer 0 ($0300-$03ff)
buffer_0 = $0300

// Buffer 1 ($0400-$04ff)
buffer_1 = $0400

// VIA 1 (serial bus) ($1800-$180f)
via1_serial_bus = $1800

// VIA 2 (disk controller) ($1c00-$1c0f)
via2_disk_control   = $1c00
via2_disk_data      = $1c01

// DOS ROM ($c000-$ffe5)
dos_idle_loop   = $ebe7
wait_for_sync   = $f556
gcr_to_binary   = $f8e0
end_job         = $f969

    * = $0500

pydis_start
drive_code
    sei                                                               // 0500: 78          .
    lda via2_disk_control                                             // 0501: ad 00 1c    ...
    ora #8                                                            // 0504: 09 08       ..
    sta via2_disk_control                                             // 0506: 8d 00 1c    ... // Turn the LED on

    // Job 0: read track 18, sector 1 into buffer 0 ($0300)
    lda #$12                                                          // 0509: a9 12       ..
    sta job_track_sector                                              // 050b: 85 06       ..
    ldx #1                                                            // 050d: a2 01       ..
    stx job_track_sector+1                                            // 050f: 86 07       ..
    lda #job_read                                                     // 0511: a9 80       ..
    sta job_queue                                                     // 0513: 85 00       ..

// $0515 referenced 1 time by $0517
loop_c0515
    lda job_queue                                                     // 0515: a5 00       ..
    bmi loop_c0515                                                    // 0517: 30 fc       0.
    cmp #job_ok                                                       // 0519: c9 01       I.
    bne c054a                                                         // 051b: d0 2d       P-

    // Job 3: move the head to track 18, then run the code in buffer 3 (job_3_code)
    ldy #$12                                                          // 051d: a0 12       ..
    sty job_track_sector+6                                            // 051f: 84 0c       ..
    lda #job_execute                                                  // 0521: a9 e0       ..
    sta job_queue+3                                                   // 0523: 85 03       ..

// $0525 referenced 1 time by $0527
loop_c0525
    lda job_queue+3                                                   // 0525: a5 03       ..
    bmi loop_c0525                                                    // 0527: 30 fc       0.

    // Job 1: move the head to track 1 (bump)
    lda #job_bump                                                     // 0529: a9 c0       ..
    sta job_queue+1                                                   // 052b: 85 01       ..

    // Copy 69 bytes of memory from buffer_0+1 to buffer_0+70
    ldy #$45 // 'e'                                                   // 052d: a0 45       .e
// $052f referenced 1 time by $0536
loop_c052f
    lda 0+(buffer_0+1) - 1,y                                          // 052f: b9 00 03    ...
    sta 0+(buffer_0+70) - 1,y                                         // 0532: 99 45 03    .e.
    dey                                                               // 0535: 88          .
    bne loop_c052f                                                    // 0536: d0 f7       P.

    // Set the NMI vector to nmi_handler
    lda #<nmi_handler                                                 // 0538: a9 49       .i
    sta nmi_vector                                                    // 053a: 85 65       ..
    lda #>nmi_handler                                                 // 053c: a9 05       ..
    sta nmi_vector+1                                                  // 053e: 85 66       ..

    lda #8                                                            // 0540: a9 08       ..
    sta via1_serial_bus                                               // 0542: 8d 00 18    ... // Release the data line, pull the clock line low, stop acknowledging ATN
    cli                                                               // 0545: 58          x
    jmp dos_idle_loop                                                 // 0546: 4c e7 eb    l.. // The DOS's main loop, waiting for a command (and running the jobs)

nmi_handler
    rti                                                               // 0549: 40          @

// $054a referenced 1 time by $051b
c054a
    lda via2_disk_control                                             // 054a: ad 00 1c    ...
    and #$f7                                                          // 054d: 29 f7       ).
    sta via2_disk_control                                             // 054f: 8d 00 1c    ... // Turn the LED off
    rts                                                               // 0552: 60          .

    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 0553: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 0567: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 057b: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 058f: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 05a3: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 05b7: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 05cb: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 05df: 00 00 00... ...
    .byt 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                        // 05f3: 00 00 00... ...

job_3_code
    lda via2_disk_control                                             // 0600: ad 00 1c    ...
    ora #$64                                                          // 0603: 09 64       ..
    sta via2_disk_control                                             // 0605: 8d 00 1c    ... // Turn the motor on, set the bit rate to 3 (for tracks 1-17)
// $0608 referenced 1 time by $060b
loop_c0608
    bit via2_disk_control                                             // 0608: 2c 00 1c    ,.. // Test SYNC (clear at a sync mark)
    bmi loop_c0608                                                    // 060b: 30 fb       0.
    jsr wait_for_sync                                                 // 060d: 20 56 f5     v. // Wait for a sync mark (20 ms at most)
// $0610 referenced 1 time by $0610
loop_c0610
    bvc loop_c0610                                                    // 0610: 50 fe       p.
    clv                                                               // 0612: b8          .
    lda via2_disk_data                                                // 0613: ad 01 1c    ...
    sta buffer_1                                                      // 0616: 8d 00 04    ...
    jsr gcr_to_binary                                                 // 0619: 20 e0 f8     .. // Convert the GCR data read into the buffer at BUFPNT to binary
    lda #job_ok                                                       // 061c: a9 01       .. // A=result (1 for OK)
    jmp end_job                                                       // 061e: 4c 69 f9    l.. // End the job, with its result (A) in the job queue

pydis_end

#if ((buffer_0+1) - 1) <> $0300
#error Assertion failed: (buffer_0+1) - 1 == $0300
#endif
#if ((buffer_0+70) - 1) <> $0345
#error Assertion failed: (buffer_0+70) - 1 == $0345
#endif
#if ((nmi_handler) & $ff) <> $49
#error Assertion failed: <nmi_handler == $49
#endif
#if (((nmi_handler) >> 8) & $ff) <> $05
#error Assertion failed: >nmi_handler == $05
#endif

// Label references by decreasing frequency:
//     via2_disk_control:   7
//     job_queue:           2
//     buffer_0:            1
//     buffer_1:            1
//     c054a:               1
//     dos_idle_loop:       1
//     end_job:             1
//     gcr_to_binary:       1
//     job_track_sector:    1
//     loop_c0515:          1
//     loop_c0525:          1
//     loop_c052f:          1
//     loop_c0608:          1
//     loop_c0610:          1
//     nmi_vector:          1
//     via1_serial_bus:     1
//     via2_disk_data:      1
//     wait_for_sync:       1

// Automatically generated labels:
//     c054a
//     loop_c0515
//     loop_c0525
//     loop_c052f
//     loop_c0608
//     loop_c0610

// Stats:
//
//     Total size (Code + Data) = 289 bytes
//     Code                     = 116 bytes (40%)
//     Data                     = 173 bytes (60%)
//
//     Number of instructions   = 53
//     Number of data bytes     = 173 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

