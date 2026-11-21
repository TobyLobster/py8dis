; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Soft switches ($c000-$c07f)
lc006           equ $c006
SET80VID        equ $c00d
SETALTCHAR      equ $c00f
MOUXINT         equ $c015
MOUYINT         equ $c017
VBLINT          equ $c019
MOUCLR          equ $c048
MOUDSBL         equ $c058
MOUENBL         equ $c059
DISVBL          equ $c05a
ENVBL           equ $c05b
DHIRESON        equ $c05e
column_switch   equ $c060
MOUBUT          equ $c063
MOUX1           equ $c066
MOUY1           equ $c067
PTRIG           equ $c070
IOUDSBL         equ $c078
RDIOUDIS        equ $c07e
RDDHIRES        equ $c07f
IOUDISOFF       equ $c07f

; Slot I/O ($c090-$c0ff)
serial_1_data   equ $c098
serial_1_status equ $c099
serial_2_data   equ $c0a8
serial_2_command equ $c0aa

; Monitor ROM ($f800-$ffff)
VERSION         equ $fbb3
iic_rom_version equ $fbbf
ZIDBYTE         equ $fbc0

    org $0803

pydis_start
start
    lda VERSION                                                       ; 0803: ad b3 fb    -3{
    cmp #6                                                            ; 0806: c9 06       I.
    bne return_1                                                      ; 0808: d0 67       P.
    lda ZIDBYTE                                                       ; 080a: ad c0 fb    -@{
    bne return_1                                                      ; 080d: d0 62       P.
    lda iic_rom_version                                               ; 080f: ad bf fb    -?{
    sta l0870                                                         ; 0812: 8d 70 08    ...
    stz SET80VID                                                      ; 0815: 9c 0d c0    ..@ ; Show 80 columns
    stz SETALTCHAR                                                    ; 0818: 9c 0f c0    ..@ ; Use the alternate character set (MouseText and inverse lower case instead of flashing)
    sta lc006                                                         ; 081b: 8d 06 c0    ..@
    sta IOUDISOFF                                                     ; 081e: 8d 7f c0    ..@ ; IOUDIS off: enable the IOU's switches ($C058-$C05D)
    sta ENVBL                                                         ; 0821: 8d 5b c0    ..@ ; Enable the vertical blank interrupt (with IOUDIS off)
    sta MOUENBL                                                       ; 0824: 8d 59 c0    ..@ ; Enable the mouse's interrupts (with IOUDIS off)
; $0827 referenced 1 time by $082a
loop_c0827
    lda VBLINT                                                        ; 0827: ad 19 c0    -.@ ; Wait for the vertical blank interrupt
    bpl loop_c0827                                                    ; 082a: 10 fb       .{
    lda PTRIG                                                         ; 082c: ad 70 c0    -.@ ; Start the paddles' timers, and clear the vertical blank interrupt
    bit MOUXINT                                                       ; 082f: 2c 15 c0    ..@ ; Test for a mouse X interrupt (bit 7 set if there was one)
    bmi c0837                                                         ; 0832: 30 03       ..
    bit MOUYINT                                                       ; 0834: 2c 17 c0    ..@ ; Test for a mouse Y interrupt (bit 7 set if there was one)
; $0837 referenced 1 time by $0832
c0837
    lda MOUCLR                                                        ; 0837: ad 48 c0    -.@ ; Clear the mouse's interrupts
    lda MOUBUT                                                        ; 083a: ad 63 c0    -.@ ; Test the mouse's button (bit 7)
    ldx MOUX1                                                         ; 083d: ae 66 c0    ..@ ; Test the mouse's X1 signal (bit 7, its direction)
    ldy MOUY1                                                         ; 0840: ac 67 c0    ,.@ ; Test the mouse's Y1 signal (bit 7, its direction)
    phx                                                               ; 0843: da          Z
    phy                                                               ; 0844: 5a          .
    sta MOUDSBL                                                       ; 0845: 8d 58 c0    ..@ ; Disable the mouse's interrupts (with IOUDIS off)
    sta DISVBL                                                        ; 0848: 8d 5a c0    ..@ ; Disable the vertical blank interrupt (with IOUDIS off)
    sta IOUDSBL                                                       ; 084b: 8d 78 c0    ..@ ; IOUDIS on: disable the IOU's switches ($C058-$C05D), enable double hi-res's
    sta DHIRESON                                                      ; 084e: 8d 5e c0    ..@ ; Turn double hi-res on (with IOUDIS on)
    lda RDIOUDIS                                                      ; 0851: ad 7e c0    -.@ ; Test whether IOUDIS is on (bit 7)
    lda RDDHIRES                                                      ; 0854: ad 7f c0    -.@ ; Test whether double hi-res is on (bit 7)
    lda column_switch                                                 ; 0857: ad 60 c0    -.@ ; Test the 40/80-column switch (bit 7)
    lda serial_1_status                                               ; 085a: ad 99 c0    -.@
    and #8                                                            ; 085d: 29 08       ..
    beq c0867                                                         ; 085f: f0 06       p.
    lda serial_1_data                                                 ; 0861: ad 98 c0    -.@
    sta serial_2_data                                                 ; 0864: 8d a8 c0    .(@
; $0867 referenced 1 time by $085f
c0867
    lda #$0b                                                          ; 0867: a9 0b       ).
    sta serial_2_command                                              ; 0869: 8d aa c0    .*@
    ply                                                               ; 086c: 7a          .
    plx                                                               ; 086d: fa          z
    bra return_1                                                      ; 086e: 80 01       ..

; $0870 referenced 1 time by $0812
l0870
    dfb 0                                                             ; 0870: 00          .

; $0871 referenced 3 times by $0808, $080d, $086e
return_1
    rts                                                               ; 0871: 60          .

pydis_end


; Label references by decreasing frequency:
;     return_1:           3
;     IOUDISOFF:          2
;     RDDHIRES:           2
;     DHIRESON:           1
;     DISVBL:             1
;     ENVBL:              1
;     IOUDSBL:            1
;     MOUBUT:             1
;     MOUCLR:             1
;     MOUDSBL:            1
;     MOUENBL:            1
;     MOUX1:              1
;     MOUXINT:            1
;     MOUY1:              1
;     MOUYINT:            1
;     PTRIG:              1
;     RDIOUDIS:           1
;     SET80VID:           1
;     SETALTCHAR:         1
;     VBLINT:             1
;     VERSION:            1
;     ZIDBYTE:            1
;     c0837:              1
;     c0867:              1
;     column_switch:      1
;     iic_rom_version:    1
;     l0870:              1
;     lc006:              1
;     loop_c0827:         1
;     serial_1_data:      1
;     serial_1_status:    1
;     serial_2_command:   1
;     serial_2_data:      1

; Automatically generated labels:
;     c0837
;     c0867
;     l0870
;     lc006
;     loop_c0827
;     return_1

; Stats:
;
;     Total size (Code + Data) = 111 bytes
;     Code                     = 110 bytes (99%)
;     Data                     = 1 bytes (1%)
;
;     Number of instructions   = 43
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
