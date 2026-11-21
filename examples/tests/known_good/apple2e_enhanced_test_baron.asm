; Assemble with Baron, which writes the program to the file named in its
; section (apple2e_enhanced_test_baron), in the folder given with -p:
;     baron -p . apple2e_enhanced_test_baron.asm

; Memory locations

; Soft switches (&c000-&c07f)
SETSLOTCXROM = &c006
SET80VID    = &c00d
SETALTCHAR  = &c00f
RDCXROM     = &c015
RDC3ROM     = &c017
RDVBLBAR    = &c019
lc048       = &c048
CLRAN0      = &c058
SETAN0      = &c059
CLRAN1      = &c05a
SETAN1      = &c05b
CLRAN3      = &c05e
TAPEIN      = &c060
BUTN2       = &c063
PADDL2      = &c066
PADDL3      = &c067
PTRIG       = &c070
lc078       = &c078
lc07e       = &c07e
lc07f       = &c07f

; Slot I/O (&c090-&c0ff)
lc098   = &c098
lc099   = &c099
lc0a8   = &c0a8
lc0aa   = &c0aa

; Monitor ROM (&f800-&ffff)
VERSION         = &fbb3
iic_rom_version = &fbbf
ZIDBYTE         = &fbc0

section pydis, org = &0803, filename = "apple2e_enhanced_test_baron", cmos = true

.pydis_start
.start
    lda VERSION                                                       ; 0803: ad b3 fb    -3{
    cmp #6                                                            ; 0806: c9 06       I.
    bne return_1                                                      ; 0808: d0 67       P.
    lda ZIDBYTE                                                       ; 080a: ad c0 fb    -@{
    bne return_1                                                      ; 080d: d0 62       P.
    lda iic_rom_version                                               ; 080f: ad bf fb    -?{
    sta l0870                                                         ; 0812: 8d 70 08    ...
    stz SET80VID                                                      ; 0815: 9c 0d c0    ..@ ; Show 80 columns
    stz SETALTCHAR                                                    ; 0818: 9c 0f c0    ..@ ; Use the alternate character set (MouseText and inverse lower case instead of flashing)
    sta SETSLOTCXROM                                                  ; 081b: 8d 06 c0    ..@ ; Use the slots' ROMs at $C100-$CFFF
    sta lc07f                                                         ; 081e: 8d 7f c0    ..@
    sta SETAN1                                                        ; 0821: 8d 5b c0    ..@ ; Turn annunciator 1 on
    sta SETAN0                                                        ; 0824: 8d 59 c0    ..@ ; Turn annunciator 0 on
; &0827 referenced 1 time by &082a
.loop_c0827
    lda RDVBLBAR                                                      ; 0827: ad 19 c0    -.@ ; Wait for the vertical blank to end
    bpl loop_c0827                                                    ; 082a: 10 fb       .{
    lda PTRIG                                                         ; 082c: ad 70 c0    -.@ ; Start the paddles' timers
    bit RDCXROM                                                       ; 082f: 2c 15 c0    ..@ ; Test whether the internal $C100-$CFFF ROM is selected (bit 7)
    bmi c0837                                                         ; 0832: 30 03       ..
    bit RDC3ROM                                                       ; 0834: 2c 17 c0    ..@ ; Test whether slot 3's ROM is selected (bit 7)
; &0837 referenced 1 time by &0832
.c0837
    lda lc048                                                         ; 0837: ad 48 c0    -.@
    lda BUTN2                                                         ; 083a: ad 63 c0    -.@ ; Test button 2 (bit 7 set if it's pressed)
    ldx PADDL2                                                        ; 083d: ae 66 c0    ..@ ; Test paddle 2's timer (bit 7 set until it runs out)
    ldy PADDL3                                                        ; 0840: ac 67 c0    ,.@ ; Test paddle 3's timer (bit 7 set until it runs out)
    phx                                                               ; 0843: da          Z
    phy                                                               ; 0844: 5a          .
    sta CLRAN0                                                        ; 0845: 8d 58 c0    ..@ ; Turn annunciator 0 off
    sta CLRAN1                                                        ; 0848: 8d 5a c0    ..@ ; Turn annunciator 1 off
    sta lc078                                                         ; 084b: 8d 78 c0    ..@
    sta CLRAN3                                                        ; 084e: 8d 5e c0    ..@ ; Turn annunciator 3 off
    lda lc07e                                                         ; 0851: ad 7e c0    -.@
    lda lc07f                                                         ; 0854: ad 7f c0    -.@
    lda TAPEIN                                                        ; 0857: ad 60 c0    -.@ ; Test the tape input (bit 7)
    lda lc099                                                         ; 085a: ad 99 c0    -.@
    and #8                                                            ; 085d: 29 08       ..
    beq c0867                                                         ; 085f: f0 06       p.
    lda lc098                                                         ; 0861: ad 98 c0    -.@
    sta lc0a8                                                         ; 0864: 8d a8 c0    .(@
; &0867 referenced 1 time by &085f
.c0867
    lda #&0b                                                          ; 0867: a9 0b       ).
    sta lc0aa                                                         ; 0869: 8d aa c0    .*@
    ply                                                               ; 086c: 7a          .
    plx                                                               ; 086d: fa          z
    bra return_1                                                      ; 086e: 80 01       ..

; &0870 referenced 1 time by &0812
.l0870
    equb 0                                                            ; 0870: 00          .

; &0871 referenced 3 times by &0808, &080d, &086e
.return_1
    rts                                                               ; 0871: 60          .

.pydis_end


endsection

; Label references by decreasing frequency:
;     return_1:          3
;     lc07f:             2
;     BUTN2:             1
;     CLRAN0:            1
;     CLRAN1:            1
;     CLRAN3:            1
;     PADDL2:            1
;     PADDL3:            1
;     PTRIG:             1
;     RDC3ROM:           1
;     RDCXROM:           1
;     RDVBLBAR:          1
;     SET80VID:          1
;     SETALTCHAR:        1
;     SETAN0:            1
;     SETAN1:            1
;     SETSLOTCXROM:      1
;     TAPEIN:            1
;     VERSION:           1
;     ZIDBYTE:           1
;     c0837:             1
;     c0867:             1
;     iic_rom_version:   1
;     l0870:             1
;     lc048:             1
;     lc078:             1
;     lc07e:             1
;     lc098:             1
;     lc099:             1
;     lc0a8:             1
;     lc0aa:             1
;     loop_c0827:        1

; Automatically generated labels:
;     c0837
;     c0867
;     l0870
;     lc048
;     lc078
;     lc07e
;     lc07f
;     lc098
;     lc099
;     lc0a8
;     lc0aa
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
