; Assemble with Baron, which writes the program to the file named in its
; section (apple2_test_baron), in the folder given with -p:
;     baron -p . apple2_test_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0006   = &0006
l0007   = &0007
CH      = &0024
CV      = &0025
INVFLG  = &0032
CSWL    = &0036
CSWH    = &0037
A1L     = &003c
A1H     = &003d
A2L     = &003e
A2H     = &003f
A4L     = &0042
A4H     = &0043

; Stack (&0100-&01ff)
l0100   = &0100

; Input buffer (&0200-&02ff)
IN  = &0200

; Vectors (&03f0-&03ff)
SOFTEV  = &03f2
IRQLOC  = &03fe

; Soft switches (&c000-&c07f)
KBD     = &c000
lc001   = &c001
lc004   = &c004
lc005   = &c005
lc00d   = &c00d
KBDSTRB = &c010
lc019   = &c019
SPKR    = &c030
TXTCLR  = &c050
HIRES   = &c057
BUTN0   = &c061

; Language card (&c080-&c08f)
lc_read_rom             = &c082
LCBANK2                 = &c083
lc_read_rom_write_ram_1 = &c089

; Slot ROMs (&c100-&c7ff)
lc311   = &c311

; Monitor ROM (&f800-&ffff)
PLOT    = &f800
SETCOL  = &f864
PRBL2   = &f94a
PREAD   = &fb1e
SETGR   = &fb40
TABV    = &fb5b
SETPWRC = &fb6f
HOME    = &fc58
WAIT    = &fca8
RDKEY   = &fd0c
GETLN   = &fd6a
CROUT   = &fd8e
PRBYTE  = &fdda
COUT    = &fded
COUT1   = &fdf0
SETNORM = &fe84
SETVID  = &fe93
OUTPORT = &fe95
BELL    = &ff3a
IORTS   = &ff58
MONZ    = &ff69

; Disk II (indexed by the slot times 16)
MOTOROFF = &c088
MOTORON = &c089
DRV0EN  = &c08a
Q6L     = &c08c
Q7L     = &c08e

section pydis, org = &0803, filename = "apple2_test_baron"

.pydis_start
.start
    jsr HOME                                                          ; 0803: 20 58 fc    ..| ; Clear the window and put the cursor at its top left
    ; print message
    ldx #0                                                            ; 0806: a2 00       ".
; &0808 referenced 1 time by &0811
.loop_c0808
    lda l0931,x                                                       ; 0808: bd 31 09    =.. ; A=character
    beq c0813                                                         ; 080b: f0 06       p.
    jsr COUT                                                          ; 080d: 20 ed fd    .m} ; Print a character (through CSW)
    inx                                                               ; 0810: e8          h
    bne loop_c0808                                                    ; 0811: d0 f5       Pu
; &0813 referenced 1 time by &080b
.c0813
    ; Print "HI"
    lda #'H' or &80                                                   ; 0813: a9 c8       )H
    jsr COUT                                                          ; 0815: 20 ed fd    .m} ; Print 'H'
    lda #'I' or &80                                                   ; 0818: a9 c9       )I
    jsr COUT                                                          ; 081a: 20 ed fd    .m} ; Print 'I'
    lda #&8d                                                          ; 081d: a9 8d       ).
    jsr COUT                                                          ; 081f: 20 ed fd    .m} ; Print a carriage return
    jsr CROUT                                                         ; 0822: 20 8e fd    ..} ; Start a new line
    ; DOS command: PR#0
    lda #&84                                                          ; 0825: a9 84       ).
    jsr COUT                                                          ; 0827: 20 ed fd    .m} ; Print Ctrl-D (to start a DOS command)
    lda #'P' or &80                                                   ; 082a: a9 d0       )P
    jsr COUT                                                          ; 082c: 20 ed fd    .m} ; Print 'P'
    lda #'R' or &80                                                   ; 082f: a9 d2       )R
    jsr COUT                                                          ; 0831: 20 ed fd    .m} ; Print 'R'
    lda #'#' or &80                                                   ; 0834: a9 a3       )#
    jsr COUT                                                          ; 0836: 20 ed fd    .m} ; Print '#'
    lda #'0' or &80                                                   ; 0839: a9 b0       )0
    jsr COUT                                                          ; 083b: 20 ed fd    .m} ; Print '0'
    lda #&8d                                                          ; 083e: a9 8d       ).
    jsr COUT                                                          ; 0840: 20 ed fd    .m} ; Print a carriage return
    lda #&12                                                          ; 0843: a9 12       ).
    jsr PRBYTE                                                        ; 0845: 20 da fd    .Z} ; Print A in hex
    ldx #5                                                            ; 0848: a2 05       ".
    jsr PRBL2                                                         ; 084a: 20 4a f9    ..y ; Print 5 spaces
    lda #&0a                                                          ; 084d: a9 0a       ).
    jsr TABV                                                          ; 084f: 20 5b fb    ..{ ; Move the cursor to row 10
    lda #&40                                                          ; 0852: a9 40       ).
    jsr WAIT                                                          ; 0854: 20 a8 fc    .(| ; Wait 11,117 cycles (about 10.9 ms)
    lda #1                                                            ; 0857: a9 01       ).
    jsr OUTPORT                                                       ; 0859: 20 95 fe    ..~ ; Send output to slot 1 (PR#1)
    jsr SETVID                                                        ; 085c: 20 93 fe    ..~ ; Send output to the screen (PR#0)
    jsr BELL                                                          ; 085f: 20 3a ff    ... ; Beep (by printing Ctrl-G)
    jsr SETGR                                                         ; 0862: 20 40 fb    ..{ ; Set lo-res mixed mode, and clear the graphics
    lda #9                                                            ; 0865: a9 09       ).
    jsr SETCOL                                                        ; 0867: 20 64 f8    ..x ; Set the lo-res colour to 9 (orange)
    lda #&0a                                                          ; 086a: a9 0a       ). ; A=row (0-47)
    ldy #5                                                            ; 086c: a0 05        . ; Y=column (0-39)
    jsr PLOT                                                          ; 086e: 20 00 f8    ..x ; Plot a lo-res block (in COLOR)
    ldx #0                                                            ; 0871: a2 00       ".
    jsr PREAD                                                         ; 0873: 20 1e fb    ..{ ; Read paddle 0
    sty l0006                                                         ; 0876: 84 06       .. ; Y=paddle's value (0-255)
    jsr RDKEY                                                         ; 0878: 20 0c fd    ..} ; Read a key (through KSW)
    cmp #&d9 ; 'Y'                                                    ; 087b: c9 d9       IY ; A=key (with bit 7 set)
    beq c0887                                                         ; 087d: f0 08       p.
    jsr GETLN                                                         ; 087f: 20 6a fd    ..} ; Input a line into IN, after PROMPT
    stx l0007                                                         ; 0882: 86 07       .. ; X=line's length
    lda IN                                                            ; 0884: ad 00 02    -..
; &0887 referenced 1 time by &087d
.c0887
    lda #5                                                            ; 0887: a9 05       ).
    sta CH                                                            ; 0889: 85 24       ..
    sta CV                                                            ; 088b: 85 25       ..
    lda #&3f                                                          ; 088d: a9 3f       ).
    sta INVFLG                                                        ; 088f: 85 32       ..
    jsr SETNORM                                                       ; 0891: 20 84 fe    ..~ ; Print in normal text

    ; Set the reset vector to 'reset_handler'
    lda #<reset_handler                                               ; 0894: a9 2a       ).
    sta SOFTEV                                                        ; 0896: 8d f2 03    .r.
    lda #>reset_handler                                               ; 0899: a9 09       ).
    sta SOFTEV+1                                                      ; 089b: 8d f3 03    .s.

    jsr SETPWRC                                                       ; 089e: 20 6f fb    ..{ ; Set PWREDUP to match SOFTEV, so that reset uses it

    ; Set the output hook (CSW) to 'output_handler'
    lda #<output_handler                                              ; 08a1: a9 2d       ).
    sta CSWL                                                          ; 08a3: 85 36       ..
    lda #>output_handler                                              ; 08a5: a9 09       ).
    sta CSWH                                                          ; 08a7: 85 37       ..

    ; Set the IRQ vector to 'irq_handler'
    lda #<irq_handler                                                 ; 08a9: a9 30       ).
    sta IRQLOC                                                        ; 08ab: 8d fe 03    .~.
    lda #>irq_handler                                                 ; 08ae: a9 09       ).
    sta IRQLOC+1                                                      ; 08b0: 8d ff 03    ...

    bit TXTCLR                                                        ; 08b3: 2c 50 c0    ..@ ; Show graphics
    bit HIRES                                                         ; 08b6: 2c 57 c0    ..@ ; Show hi-res graphics
    lda SPKR                                                          ; 08b9: ad 30 c0    -.@ ; Click the speaker
; &08bc referenced 1 time by &08bf
.loop_c08bc
    lda KBD                                                           ; 08bc: ad 00 c0    -.@ ; Wait for a key
    bpl loop_c08bc                                                    ; 08bf: 10 fb       .{
    sta KBDSTRB                                                       ; 08c1: 8d 10 c0    ..@ ; Clear the keyboard strobe
    lda BUTN0                                                         ; 08c4: ad 61 c0    -.@ ; Test button 0 (bit 7 set if it's pressed)
    bmi c08c9                                                         ; 08c7: 30 00       ..
; &08c9 referenced 2 times by &08c7, &08cc
.c08c9
    lda lc019                                                         ; 08c9: ad 19 c0    -.@
    bpl c08c9                                                         ; 08cc: 10 fb       .{
    lda #0                                                            ; 08ce: a9 00       ).
    sta A1L                                                           ; 08d0: 85 3c       ..
    lda #&20                                                          ; 08d2: a9 20       ).
    sta A1H                                                           ; 08d4: 85 3d       ..
    lda #&ff                                                          ; 08d6: a9 ff       ).
    sta A2L                                                           ; 08d8: 85 3e       ..
    lda #&3f                                                          ; 08da: a9 3f       ).
    sta A2H                                                           ; 08dc: 85 3f       ..
    lda #0                                                            ; 08de: a9 00       ).
    sta A4L                                                           ; 08e0: 85 42       ..
    lda #&20                                                          ; 08e2: a9 20       ).
    sta A4H                                                           ; 08e4: 85 43       ..
    sec                                                               ; 08e6: 38          .
    jsr lc311                                                         ; 08e7: 20 11 c3    ..C
; &08ea referenced 1 time by &08ed
.loop_c08ea
    lda lc019                                                         ; 08ea: ad 19 c0    -.@
    bmi loop_c08ea                                                    ; 08ed: 30 fb       .{
    lda LCBANK2                                                       ; 08ef: ad 83 c0    -.@ ; Language card: read and write RAM bank 2 (two reads in a row enable writing)
    lda LCBANK2                                                       ; 08f2: ad 83 c0    -.@ ; Language card: read and write RAM bank 2 (two reads in a row enable writing)
    lda lc_read_rom                                                   ; 08f5: ad 82 c0    -.@ ; Language card: read ROM, no writing
    lda lc_read_rom_write_ram_1                                       ; 08f8: ad 89 c0    -.@ ; Language card: read ROM, write RAM bank 1 (two reads in a row enable writing)
    lda lc_read_rom_write_ram_1                                       ; 08fb: ad 89 c0    -.@ ; Language card: read ROM, write RAM bank 1 (two reads in a row enable writing)
    sta lc00d                                                         ; 08fe: 8d 0d c0    ..@
    sta lc001                                                         ; 0901: 8d 01 c0    ..@
    sta KBD                                                           ; 0904: 8d 00 c0    ..@
    sta lc005                                                         ; 0907: 8d 05 c0    ..@
    sta lc004                                                         ; 090a: 8d 04 c0    ..@
    ldx #&60                                                          ; 090d: a2 60       ".
    lda MOTORON,x                                                     ; 090f: bd 89 c0    =.@ ; Disk II: turn the motor on
    lda DRV0EN,x                                                      ; 0912: bd 8a c0    =.@ ; Disk II: select drive 1
    lda Q7L,x                                                         ; 0915: bd 8e c0    =.@ ; Disk II: Q7 low (read mode)
; &0918 referenced 1 time by &091b
.loop_c0918
    lda Q6L,x                                                         ; 0918: bd 8c c0    =.@ ; Disk II: Q6 low (read the data latch)
    bpl loop_c0918                                                    ; 091b: 10 fb       .{
    lda MOTOROFF,x                                                    ; 091d: bd 88 c0    =.@ ; Disk II: turn the motor off
    jsr IORTS                                                         ; 0920: 20 58 ff    ... ; Return (an RTS: code calls it to find its own address on the stack)
    tsx                                                               ; 0923: ba          :
    lda l0100,x                                                       ; 0924: bd 00 01    =..
    jmp MONZ                                                          ; 0927: 4c 69 ff    ... ; Enter the Monitor

.reset_handler
    jmp MONZ                                                          ; 092a: 4c 69 ff    ... ; Enter the Monitor

.output_handler
    jmp COUT1                                                         ; 092d: 4c f0 fd    .p} ; Print a character on the screen

.irq_handler
    rti                                                               ; 0930: 40          .

; &0931 referenced 1 time by &0808
.l0931
    equb &c8, &c5, &cc, &cc, &cf, &ac, &a0, &d7 ; apple "HELLO, W"    ; 0931: c8 c5 cc... HEL
    equb &cf, &d2, &cc, &c4 ; apple "ORLD"                            ; 0939: cf d2 cc... ORL
    equb &8d, 0                                                       ; 093d: 8d 00       ..
.pydis_end

    assert (<irq_handler) = &30
    assert (<output_handler) = &2d
    assert (<reset_handler) = &2a
    assert (>irq_handler) = &09
    assert (>output_handler) = &09
    assert (>reset_handler) = &09

endsection

; Label references by decreasing frequency:
;     COUT:                     10
;     MOTORON:                   3
;     lc_read_rom_write_ram_1:   3
;     KBD:                       2
;     LCBANK2:                   2
;     MONZ:                      2
;     c08c9:                     2
;     lc019:                     2
;     A1H:                       1
;     A1L:                       1
;     A2H:                       1
;     A2L:                       1
;     A4H:                       1
;     A4L:                       1
;     BELL:                      1
;     BUTN0:                     1
;     CH:                        1
;     COUT1:                     1
;     CROUT:                     1
;     CSWH:                      1
;     CSWL:                      1
;     CV:                        1
;     DRV0EN:                    1
;     GETLN:                     1
;     HIRES:                     1
;     HOME:                      1
;     IN:                        1
;     INVFLG:                    1
;     IORTS:                     1
;     IRQLOC:                    1
;     KBDSTRB:                   1
;     MOTOROFF:                  1
;     OUTPORT:                   1
;     PLOT:                      1
;     PRBL2:                     1
;     PRBYTE:                    1
;     PREAD:                     1
;     Q6L:                       1
;     Q7L:                       1
;     RDKEY:                     1
;     SETCOL:                    1
;     SETGR:                     1
;     SETNORM:                   1
;     SETPWRC:                   1
;     SETVID:                    1
;     SOFTEV:                    1
;     SPKR:                      1
;     TABV:                      1
;     TXTCLR:                    1
;     WAIT:                      1
;     c0813:                     1
;     c0887:                     1
;     l0006:                     1
;     l0007:                     1
;     l0100:                     1
;     l0931:                     1
;     lc001:                     1
;     lc004:                     1
;     lc005:                     1
;     lc00d:                     1
;     lc311:                     1
;     lc_read_rom:               1
;     loop_c0808:                1
;     loop_c08bc:                1
;     loop_c08ea:                1
;     loop_c0918:                1

; Automatically generated labels:
;     c0813
;     c0887
;     c08c9
;     l0006
;     l0007
;     l0100
;     l0931
;     lc001
;     lc004
;     lc005
;     lc00d
;     lc019
;     lc311
;     loop_c0808
;     loop_c08bc
;     loop_c08ea
;     loop_c0918

; Stats:
;
;     Total size (Code + Data) = 316 bytes
;     Code                     = 302 bytes (96%)
;     Data                     = 14 bytes (4%)
;
;     Number of instructions   = 122
;     Number of data bytes     = 2 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 12 bytes
;     Number of strings        = 1
