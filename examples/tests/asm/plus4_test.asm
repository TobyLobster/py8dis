; A Plus/4 program for commodore.plus4() (see python/plus4_test.py): a BASIC
; program that SYSes to the machine code, which prints with PRIMM, uses the
; TED (colours, sound, the keyboard and the ROM switch), the screen and its
; colour RAM and the ACIA, and sets the IRQ vector. Assemble with:
;
;   acme -f cbm -o ../orig/plus4_test.orig plus4_test.asm
;
; (It isn't meant to do anything useful when run.)

primm   = $ff4f
chrout  = $ffd2
getin   = $ffe4

    * = $1001

; The BASIC program: 10 SYS4109
line10
    !word basic_end
    !word 10
    !byte $9e               ; SYS
    !pet "4109", 0
basic_end
    !word 0

start
!if start != 4109 { !error "start isn't at 4109, as the SYS says" }
    ; Print with PRIMM, and CHROUT
    jsr primm
    !pet "hello, plus/4", 13, 0
    lda #$93
    jsr chrout

    ; The TED: the border and background colours, and a sound
    lda #$71
    sta $ff19
    lda #$00
    sta $ff15
    lda #$80
    sta $ff0e
    lda #$1f
    sta $ff11

    ; The keyboard, through the TED's latch
    lda #$7f
    sta $fd30
    sta $ff08
    lda $ff08
    sta keys

    ; The screen and its colour RAM
    ldx #39
fill_loop
    lda #$51
    sta $0c00,x
    lda #$71
    sta $0800,x
    dex
    bpl fill_loop

    ; The ACIA's status
    lda $fd01
    sta acia_status

    ; The IRQ vector
    sei
    lda #<irq
    sta $0314
    lda #>irq
    sta $0315
    cli

    ; RAM in place of the ROMs, and back
    sta $ff3f
    lda $c000
    sta $ff3e
    jsr getin
    rts

irq
    inc $ff19
    jmp $fcc3

keys
    !byte 0
acia_status
    !byte 0
