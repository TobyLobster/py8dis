; A IIe program for python/smartport_test.py (with apple.smartport_calls()):
; it turns on 80 columns (by calling slot 3's ROM, as PR#3 does), finds
; SmartPort in slot 5 by its ID bytes, sets its own JMP to the dispatcher,
; and makes SmartPort calls through it: STATUS, READBLOCK, WRITEBLOCK,
; CONTROL, INIT, READ, a call SmartPort doesn't define (a device's own),
; and an extended call, which isn't decoded. Then it boots slot 6. Assemble
; with:
;
;   acme -o ../orig/smartport_test.orig smartport_test.asm
;
; (It isn't meant to do anything useful when run.)

cout    = $fded

    * = $0803

start
    jsr $c300

    ; Is there SmartPort in slot 5?
    lda $c501
    cmp #$20
    bne no_smartport
    lda $c507
    bne no_smartport
    lda $c5ff
    clc
    adc #3
    sta smartport + 1
    lda #$c5
    sta smartport + 2

    jsr smartport
    !byte $00               ; STATUS
    !word status_params
    bcs error
    jsr smartport
    !byte $01               ; READBLOCK
    !word read_params
    jsr smartport
    !byte $02               ; WRITEBLOCK
    !word write_params
    jsr smartport
    !byte $04               ; CONTROL
    !word control_params
    jsr smartport
    !byte $05               ; INIT
    !word init_params
    jsr smartport
    !byte $08               ; READ
    !word read_bytes_params
    jsr smartport
    !byte $20               ; (a device's own call)
    !word read_params
    jmp $c600

no_smartport
    jsr smartport
    !byte $41               ; extended READBLOCK
    !word read_params, 0

error
    jsr cout
    rts

smartport
    jmp $0000               ; (set to SmartPort's dispatcher)

status_params
    !byte 3
    !byte 0                 ; unit (0: SmartPort itself)
    !word status_list
    !byte 0                 ; status code
read_params
    !byte 3
    !byte 1
    !word $2000
    !byte 0, 0, 0
write_params
    !byte 3
    !byte 1
    !word $2000
    !byte 1, 0, 0
control_params
    !byte 3
    !byte 1
    !word control_list
    !byte 4                 ; control code
init_params
    !byte 1
    !byte 0
read_bytes_params
    !byte 4
    !byte 2
    !word $2200
    !word 512
    !byte 0, 0, 0

status_list
    !fill 8, 0
control_list
    !byte 0, 0
