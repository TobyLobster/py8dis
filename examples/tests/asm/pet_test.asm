; A PET program, for python/pet_test.py etc., assembled for each BASIC
; version (the workspace and ROM addresses differ):
;
;   acme -f cbm -DBASIC=4 -DCOLUMNS=80 -o ../orig/pet4_test.orig pet_test.asm
;   acme -f cbm -DBASIC=2 -DCOLUMNS=40 -o ../orig/pet2_test.orig pet_test.asm
;   acme -f cbm -DBASIC=1 -DCOLUMNS=40 -o ../orig/pet1_test.orig pet_test.asm

!if BASIC = 1 {
cinv    = $0219         ; the IRQ vector
ndx     = $020d         ; the keyboard buffer length
rvs     = $020e         ; reverse on
key     = $e685         ; the Kernal's IRQ handler
strout  = $ca27
linprt  = $dc9f
} else {
cinv    = $90
ndx     = $9e
rvs     = $9f
!if BASIC = 2 {
key     = $e62e
strout  = $ca1c
linprt  = $dcd9
} else {
key     = $e455
strout  = $bb1d
linprt  = $cf83
}
}

chrout  = $ffd2
getin   = $ffe4
stop    = $ffe1
clrchn  = $ffcc
screen  = $8000

pia1_port_a = $e810
pia1_port_b = $e812
via_pcr     = $e84c
crtc_address = $e880
crtc_data   = $e881

    * = $0401

; The BASIC program: 10 SYS1056 (then on BASIC 4, 20 CATALOG)
line10
    !word line20
    !word 10
    !byte $9e           ; SYS
    !pet "1056", 0
line20
!if BASIC = 4 {
    !word basic_end
    !word 20
    !byte $d7           ; CATALOG
    !byte 0
}
basic_end
    !word 0

    !fill $0420 - *, 0

start
!if start != 1056 { !error "start isn't at 1056, as the SYS says" }
    ; Clear the screen, then print a message and a number
    lda #$93
    jsr chrout
    lda #<message
    ldy #>message
    jsr strout
    lda #>1234
    ldx #<1234
    jsr linprt

    ; An IRQ handler
    sei
    lda #<irq
    sta cinv
    lda #>irq
    sta cinv+1
    cli

    ; Lower case (the VIA's CA2), on BASIC 2 and 4
!if BASIC > 1 {
    lda #14
    sta via_pcr
}

!if COLUMNS = 80 {
    ; The CRTC: the screen's start address (register 12)
    lda #12
    sta crtc_address
    lda #$10
    sta crtc_data
}

    ; Reverse on, and a character on the screen
    lda #1
    sta rvs
    lda #'a'
    sta screen

    ; Wait for a key (or STOP), with the keyboard buffer emptied first
    lda #0
    sta ndx
wait
    jsr stop
    beq done
    jsr getin
    beq wait
    jsr chrout
done
    jsr clrchn
    ; Read a keyboard row directly
    lda #9
    sta pia1_port_a
    lda pia1_port_b
    rts

irq
    inc screen + 39
    jmp key

message
    !pet "hello, pet", 13, 0
