; A 65C02 program for python/apple2c_test.py (with apple.apple2(model="iic"))
; and python/apple2e_enhanced_test.py (the same program, with
; model="iie-enhanced"; the go script copies it): the ROM's ID bytes, the
; 65C02's STZ on the IIe's write switches, the IIc's mouse and vertical
; blank interrupt switches, IOUDIS, double hi-res, the 40/80-column switch,
; and the serial ports. Assemble with:
;
;   acme -o ../orig/apple2c_test.orig apple2c_test.asm
;
; (It isn't meant to do anything useful when run.)

    !cpu 65c02

version     = $fbb3
iic_version = $fbbf
zidbyte     = $fbc0

    * = $0803

start
    ; Is this a IIc? (VERSION is $06 on the IIe and IIc, and ZIDBYTE $00 on
    ; the IIc)
    lda version
    cmp #$06
    bne done
    lda zidbyte
    bne done
    lda iic_version
    sta rom_version

    ; 80 columns, the alternate character set, and the slots' ROMs (which
    ; the IIc doesn't have)
    stz $c00d
    stz $c00f
    sta $c006

    ; Turn IOUDIS off, enable the interrupts and wait for the vertical blank
    sta $c07f
    sta $c05b
    sta $c059
wait_vbl
    lda $c019
    bpl wait_vbl
    lda $c070

    ; The mouse
    bit $c015
    bmi x_moved
    bit $c017
x_moved
    lda $c048
    lda $c063
    ldx $c066
    ldy $c067
    phx
    phy
    sta $c058
    sta $c05a

    ; Turn IOUDIS on, and double hi-res on
    sta $c078
    sta $c05e
    lda $c07e
    lda $c07f
    lda $c060

    ; The serial ports
    lda $c099
    and #$08
    beq no_byte
    lda $c098
    sta $c0a8
no_byte
    lda #$0b
    sta $c0aa
    ply
    plx
    bra done

rom_version
    !byte 0

done
    rts
