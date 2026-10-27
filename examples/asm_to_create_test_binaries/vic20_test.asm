; A VIC-20 program for commodore.vic20() (see python/vic20_test.py and
; vic20_8k_test.py): a BASIC program that SYSes to the machine code, which
; sets the IRQ vector, uses the VIC, the VIAs, the screen and its colour RAM,
; and calls the Kernal and BASIC's ROM routines. Assembled twice: for an
; unexpanded VIC-20 (loaded at $1001, the screen at $1e00), and with 8K or
; more RAM (loaded at $1201, the screen at $1000):
;
;   acme -f cbm -o ../orig/vic20_test.orig vic20_test.asm
;   acme -f cbm -DEXPANDED=1 -o ../orig/vic20_8k_test.orig vic20_test.asm
;
; (It isn't meant to do anything useful when run.)

!ifndef EXPANDED { EXPANDED = 0 }

chrout  = $ffd2
plot    = $fff0
getin   = $ffe4
setlfs  = $ffba
strout  = $cb1e
linprt  = $ddcd

!if EXPANDED {
    screen     = $1000
    colour_ram = $9400
    * = $1201
} else {
    screen     = $1e00
    colour_ram = $9600
    * = $1001
}

; The BASIC program: 10 SYS<start>
line10
    !word basic_end
    !word 10
    !byte $9e               ; SYS
!if EXPANDED {
    !pet "4621", 0
} else {
    !pet "4109", 0
}
basic_end
    !word 0

start
!if EXPANDED {
    !if start != 4621 { !error "start isn't at 4621, as the SYS says" }
} else {
    !if start != 4109 { !error "start isn't at 4109, as the SYS says" }
}
    ; The IRQ vector
    sei
    lda #<irq
    sta $0314
    lda #>irq
    sta $0315
    cli

    ; The VIC: the screen and border colours, the volume and a voice
    lda #$08
    sta $900f
    lda #$0f
    sta $900e
    lda #$c8
    sta $900c

    ; The text colour, then print a message and a character
    lda #2
    sta $0286
    lda #$93
    jsr chrout
    ldx #0
print_loop
    lda message,x
    beq printed
    jsr chrout
    inx
    bne print_loop
printed
    clc
    ldx #10
    ldy #5
    jsr plot

    ; Fill a row of the screen and its colour RAM
    ldx #21
fill_loop
    lda #$51
    sta screen,x
    lda #6
    sta colour_ram,x
    dex
    bpl fill_loop

    ; The joystick (VIA 1) and the keyboard (VIA 2)
    lda #0
    sta $9113
    lda $9111
    sta joystick
    lda #$7f
    sta $9120
    lda $9121
    sta keys

    ; The Kernal and BASIC's ROM
    jsr getin
    sta key
    lda #<basic_message
    ldy #>basic_message
    jsr strout
    lda #0
    ldx #20
    jsr linprt
    rts

irq
    inc $900f
    jmp $eabf

message
    !pet "vic-20", 13, 0
basic_message
    !pet "the answer is ", 0
joystick
    !byte 0
keys
    !byte 0
key
    !byte 0
