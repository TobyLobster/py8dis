// Memory locations

// Zero page ($0000-$00ff)
l0006   = $0006
l0007   = $0007
CH      = $0024
CV      = $0025
INVFLG  = $0032
CSWL    = $0036
CSWH    = $0037
A1L     = $003c
A1H     = $003d
A2L     = $003e
A2H     = $003f
A4L     = $0042
A4H     = $0043

// Stack ($0100-$01ff)
l0100   = $0100

// Input buffer ($0200-$02ff)
IN  = $0200

// Vectors ($03f0-$03ff)
SOFTEV  = $03f2
IRQLOC  = $03fe

// Soft switches ($c000-$c07f)
KBD     = $c000
KBDSTRB = $c010
lc019   = $c019
SPKR    = $c030
TXTCLR  = $c050
HIRES   = $c057
BUTN0   = $c061

// Slot ROMs ($c100-$c7ff)
lc311   = $c311

// Monitor ROM ($f800-$ffff)
PLOT    = $f800
SETCOL  = $f864
PRBL2   = $f94a
PREAD   = $fb1e
SETGR   = $fb40
TABV    = $fb5b
SETPWRC = $fb6f
HOME    = $fc58
WAIT    = $fca8
RDKEY   = $fd0c
GETLN   = $fd6a
CROUT   = $fd8e
PRBYTE  = $fdda
COUT    = $fded
COUT1   = $fdf0
SETNORM = $fe84
SETVID  = $fe93
OUTPORT = $fe95
BELL    = $ff3a
IORTS   = $ff58
MONZ    = $ff69

    * = $0803

pydis_start
start
    jsr HOME                                                          // 0803: 20 58 fc    ..| // Clear the window and put the cursor at its top left
    // print message
    ldx #0                                                            // 0806: a2 00       ".
// $0808 referenced 1 time by $0811
loop_c0808
    lda l08fb,x                                                       // 0808: bd fb 08    ={. // A=character
    beq c0813                                                         // 080b: f0 06       p.
    jsr COUT                                                          // 080d: 20 ed fd    .m} // Print a character (through CSW)
    inx                                                               // 0810: e8          h
    bne loop_c0808                                                    // 0811: d0 f5       Pu
// $0813 referenced 1 time by $080b
c0813
    // Print "HI"
    lda #'H' | $80                                                    // 0813: a9 c8       )H
    jsr COUT                                                          // 0815: 20 ed fd    .m} // Print 'H'
    lda #'I' | $80                                                    // 0818: a9 c9       )I
    jsr COUT                                                          // 081a: 20 ed fd    .m} // Print 'I'
    lda #$8d                                                          // 081d: a9 8d       ).
    jsr COUT                                                          // 081f: 20 ed fd    .m} // Print a carriage return
    jsr CROUT                                                         // 0822: 20 8e fd    ..} // Start a new line
    // DOS command: PR#0
    lda #$84                                                          // 0825: a9 84       ).
    jsr COUT                                                          // 0827: 20 ed fd    .m} // Print Ctrl-D (to start a DOS command)
    lda #'P' | $80                                                    // 082a: a9 d0       )P
    jsr COUT                                                          // 082c: 20 ed fd    .m} // Print 'P'
    lda #'R' | $80                                                    // 082f: a9 d2       )R
    jsr COUT                                                          // 0831: 20 ed fd    .m} // Print 'R'
    lda #'#' | $80                                                    // 0834: a9 a3       )#
    jsr COUT                                                          // 0836: 20 ed fd    .m} // Print '#'
    lda #'0' | $80                                                    // 0839: a9 b0       )0
    jsr COUT                                                          // 083b: 20 ed fd    .m} // Print '0'
    lda #$8d                                                          // 083e: a9 8d       ).
    jsr COUT                                                          // 0840: 20 ed fd    .m} // Print a carriage return
    lda #$12                                                          // 0843: a9 12       ).
    jsr PRBYTE                                                        // 0845: 20 da fd    .Z} // Print A in hex
    ldx #5                                                            // 0848: a2 05       ".
    jsr PRBL2                                                         // 084a: 20 4a f9    ..y // Print 5 spaces
    lda #$0a                                                          // 084d: a9 0a       ).
    jsr TABV                                                          // 084f: 20 5b fb    ..{ // Move the cursor to row 10
    lda #$40                                                          // 0852: a9 40       ).
    jsr WAIT                                                          // 0854: 20 a8 fc    .(| // Wait 11,117 cycles (about 10.9 ms)
    lda #1                                                            // 0857: a9 01       ).
    jsr OUTPORT                                                       // 0859: 20 95 fe    ..~ // Send output to slot 1 (PR#1)
    jsr SETVID                                                        // 085c: 20 93 fe    ..~ // Send output to the screen (PR#0)
    jsr BELL                                                          // 085f: 20 3a ff    ... // Beep (by printing Ctrl-G)
    jsr SETGR                                                         // 0862: 20 40 fb    ..{ // Set lo-res mixed mode, and clear the graphics
    lda #9                                                            // 0865: a9 09       ).
    jsr SETCOL                                                        // 0867: 20 64 f8    ..x // Set the lo-res colour to 9 (orange)
    lda #$0a                                                          // 086a: a9 0a       ). // A=row (0-47)
    ldy #5                                                            // 086c: a0 05        . // Y=column (0-39)
    jsr PLOT                                                          // 086e: 20 00 f8    ..x // Plot a lo-res block (in COLOR)
    ldx #0                                                            // 0871: a2 00       ".
    jsr PREAD                                                         // 0873: 20 1e fb    ..{ // Read paddle 0
    sty l0006                                                         // 0876: 84 06       .. // Y=paddle's value (0-255)
    jsr RDKEY                                                         // 0878: 20 0c fd    ..} // Read a key (through KSW)
    cmp #$d9 // 'Y'                                                   // 087b: c9 d9       IY // A=key (with bit 7 set)
    beq c0887                                                         // 087d: f0 08       p.
    jsr GETLN                                                         // 087f: 20 6a fd    ..} // Input a line into IN, after PROMPT
    stx l0007                                                         // 0882: 86 07       .. // X=line's length
    lda IN                                                            // 0884: ad 00 02    -..
// $0887 referenced 1 time by $087d
c0887
    lda #5                                                            // 0887: a9 05       ).
    sta CH                                                            // 0889: 85 24       ..
    sta CV                                                            // 088b: 85 25       ..
    lda #$3f                                                          // 088d: a9 3f       ).
    sta INVFLG                                                        // 088f: 85 32       ..
    jsr SETNORM                                                       // 0891: 20 84 fe    ..~ // Print in normal text

    // Set the reset vector to 'reset_handler'
    lda #<reset_handler                                               // 0894: a9 f4       )t
    sta SOFTEV                                                        // 0896: 8d f2 03    .r.
    lda #>reset_handler                                               // 0899: a9 08       ).
    sta SOFTEV+1                                                      // 089b: 8d f3 03    .s.

    jsr SETPWRC                                                       // 089e: 20 6f fb    ..{ // Set PWREDUP to match SOFTEV, so that reset uses it

    // Set the output hook (CSW) to 'output_handler'
    lda #<output_handler                                              // 08a1: a9 f7       )w
    sta CSWL                                                          // 08a3: 85 36       ..
    lda #>output_handler                                              // 08a5: a9 08       ).
    sta CSWH                                                          // 08a7: 85 37       ..

    // Set the IRQ vector to 'irq_handler'
    lda #<irq_handler                                                 // 08a9: a9 fa       )z
    sta IRQLOC                                                        // 08ab: 8d fe 03    .~.
    lda #>irq_handler                                                 // 08ae: a9 08       ).
    sta IRQLOC+1                                                      // 08b0: 8d ff 03    ...

    bit TXTCLR                                                        // 08b3: 2c 50 c0    ..@
    bit HIRES                                                         // 08b6: 2c 57 c0    ..@
    lda SPKR                                                          // 08b9: ad 30 c0    -.@
// $08bc referenced 1 time by $08bf
loop_c08bc
    lda KBD                                                           // 08bc: ad 00 c0    -.@
    bpl loop_c08bc                                                    // 08bf: 10 fb       .{
    sta KBDSTRB                                                       // 08c1: 8d 10 c0    ..@
    lda BUTN0                                                         // 08c4: ad 61 c0    -.@
    bmi c08c9                                                         // 08c7: 30 00       ..
// $08c9 referenced 2 times by $08c7, $08cc
c08c9
    lda lc019                                                         // 08c9: ad 19 c0    -.@
    bpl c08c9                                                         // 08cc: 10 fb       .{
    lda #0                                                            // 08ce: a9 00       ).
    sta A1L                                                           // 08d0: 85 3c       ..
    lda #$20                                                          // 08d2: a9 20       ).
    sta A1H                                                           // 08d4: 85 3d       ..
    lda #$ff                                                          // 08d6: a9 ff       ).
    sta A2L                                                           // 08d8: 85 3e       ..
    lda #$3f                                                          // 08da: a9 3f       ).
    sta A2H                                                           // 08dc: 85 3f       ..
    lda #0                                                            // 08de: a9 00       ).
    sta A4L                                                           // 08e0: 85 42       ..
    lda #$20                                                          // 08e2: a9 20       ).
    sta A4H                                                           // 08e4: 85 43       ..
    sec                                                               // 08e6: 38          .
    jsr lc311                                                         // 08e7: 20 11 c3    ..C
    jsr IORTS                                                         // 08ea: 20 58 ff    ... // Return (an RTS: code calls it to find its own address on the stack)
    tsx                                                               // 08ed: ba          :
    lda l0100,x                                                       // 08ee: bd 00 01    =..
    jmp MONZ                                                          // 08f1: 4c 69 ff    ... // Enter the Monitor

reset_handler
    jmp MONZ                                                          // 08f4: 4c 69 ff    ... // Enter the Monitor

output_handler
    jmp COUT1                                                         // 08f7: 4c f0 fd    .p} // Print a character on the screen

irq_handler
    rti                                                               // 08fa: 40          .

// $08fb referenced 1 time by $0808
l08fb
    .byt $c8, $c5, $cc, $cc, $cf, $ac, $a0, $d7 // apple "HELLO, W"   // 08fb: c8 c5 cc... HEL
    .byt $cf, $d2, $cc, $c4 // apple "ORLD"                           // 0903: cf d2 cc... ORL
    .byt $8d, 0                                                       // 0907: 8d 00       ..
pydis_end

#if ((irq_handler) & $ff) <> $fa
#error Assertion failed: <irq_handler == $fa
#endif
#if ((output_handler) & $ff) <> $f7
#error Assertion failed: <output_handler == $f7
#endif
#if ((reset_handler) & $ff) <> $f4
#error Assertion failed: <reset_handler == $f4
#endif
#if (((irq_handler) >> 8) & $ff) <> $08
#error Assertion failed: >irq_handler == $08
#endif
#if (((output_handler) >> 8) & $ff) <> $08
#error Assertion failed: >output_handler == $08
#endif
#if (((reset_handler) >> 8) & $ff) <> $08
#error Assertion failed: >reset_handler == $08
#endif

// Label references by decreasing frequency:
//     COUT:        10
//     MONZ:         2
//     c08c9:        2
//     A1H:          1
//     A1L:          1
//     A2H:          1
//     A2L:          1
//     A4H:          1
//     A4L:          1
//     BELL:         1
//     BUTN0:        1
//     CH:           1
//     COUT1:        1
//     CROUT:        1
//     CSWH:         1
//     CSWL:         1
//     CV:           1
//     GETLN:        1
//     HIRES:        1
//     HOME:         1
//     IN:           1
//     INVFLG:       1
//     IORTS:        1
//     IRQLOC:       1
//     KBD:          1
//     KBDSTRB:      1
//     OUTPORT:      1
//     PLOT:         1
//     PRBL2:        1
//     PRBYTE:       1
//     PREAD:        1
//     RDKEY:        1
//     SETCOL:       1
//     SETGR:        1
//     SETNORM:      1
//     SETPWRC:      1
//     SETVID:       1
//     SOFTEV:       1
//     SPKR:         1
//     TABV:         1
//     TXTCLR:       1
//     WAIT:         1
//     c0813:        1
//     c0887:        1
//     l0006:        1
//     l0007:        1
//     l0100:        1
//     l08fb:        1
//     lc019:        1
//     lc311:        1
//     loop_c0808:   1
//     loop_c08bc:   1

// Automatically generated labels:
//     c0813
//     c0887
//     c08c9
//     l0006
//     l0007
//     l0100
//     l08fb
//     lc019
//     lc311
//     loop_c0808
//     loop_c08bc

// Stats:
//
//     Total size (Code + Data) = 262 bytes
//     Code                     = 248 bytes (95%)
//     Data                     = 14 bytes (5%)
//
//     Number of instructions   = 103
//     Number of data bytes     = 2 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 12 bytes
//     Number of strings        = 1

