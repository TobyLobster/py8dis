; Four cards' ROMs, at $C200-$C5FF, for python/slot_roms_test.py (with
; apple.slot_rom() for each slot): a Pascal 1.1 serial card in slot 2, a
; card with no ID bytes in slot 3, a mouse card in slot 4, and a SmartPort
; device (a ProDOS block device) in slot 5, whose boot code makes a
; SmartPort call. Each uses its slot's I/O, as an absolute address and
; indexed by the slot times 16. Assemble with:
;
;   acme -o ../orig/slot_roms_test.orig slot_roms_test.asm
;
; (It isn't meant to do anything useful when run.)

iorts   = $ff58
cout    = $fded

; ************************************************************************
; Slot 2: a Pascal 1.1 serial card (device signature $31)

    * = $c200

    bit iorts               ; (sets V)
    bvs basic2
    sec                     ; $C205: BASIC's input entry (ID byte $38)
    !byte $90               ; (BCC, whose operand is the next byte)
    clc                     ; $C207: BASIC's output entry (ID byte $18)
    jmp basic2
    !byte $01               ; $C20B: generic signature
    !byte $31               ; $C20C: device signature
    !byte <pinit2, <pread2, <pwrite2, <pstatus2

pinit2
    ldx #0
    rts
pread2
    lda $c0a8
    ldx #0
    rts
pwrite2
    sta $c0a8
    ldx #0
    rts
basic2                      ; ($C220, where the BCC would go)
    ldx #$20
    lda $c089,x
    rts
pstatus2
    lda $c0a9
    and #$10
    ldx #0
    rts

; ************************************************************************
; Slot 3: a card with no ID bytes

    !fill $c300 - *, 0

    lda #$8d
    jsr cout
    lda $c0b0
    rts

; ************************************************************************
; Slot 4: a mouse card (device signature $20)

    !fill $c400 - *, 0

    bit iorts
    bvs basic4
    sec                     ; $C405
    !byte $90
    clc                     ; $C407
    jmp basic4
    !byte $01               ; $C40B
    !byte $20               ; $C40C: the mouse
    !byte <pinit4, <pread4, <pwrite4, <pstatus4
    !byte 0                 ; $C411
    !byte <setmouse, <servemouse, <readmouse, <clearmouse
    !byte <posmouse, <clampmouse, <homemouse, <initmouse

pinit4
pread4
pwrite4
    lda #0
    ldx #3                  ; (not supported)
    sec
    rts
basic4                      ; ($C420, where the BCC would go)
    rts
pstatus4
    ldx #0
    clc
    rts
setmouse
    sta $c0c0
    clc
    rts
servemouse
    lda $c0c1
    clc
    rts
readmouse
    lda $c0c2
    sta $0478+4
    clc
    rts
clearmouse
posmouse
clampmouse
homemouse
    clc
    rts
initmouse
    sta $c0c3
    clc
    rts

; ************************************************************************
; Slot 5: a SmartPort device

    !fill $c500 - *, 0

    ldx #$20                ; ID bytes $20, $00, $03 and $00
    ldx #$00
    ldx #$03
    ldx #$00
    lda #$c5                ; (this card is using the expansion ROM)
    sta $07f8
    ldx #$50
    lda $c08e,x
    jsr smartport5
    !byte $01               ; READBLOCK
    !word read_params5
    bcs boot_error
    jmp $0801
boot_error
    lda $c0d0
    rts

driver5
    jmp prodos5
smartport5                  ; (the driver's address plus 3)
    tsx
    lda $0101,x
    clc
    rts

prodos5
    lda $42                 ; command
    ldx $43                 ; unit
    lda ($44),y             ; buffer
    lda $46                 ; block
    lda #0
    clc
    rts

read_params5
    !byte 3
    !byte 1                 ; unit
    !word $0800             ; buffer
    !byte 0, 0, 0           ; block

    !fill $c5fc - *, 0
    !word 0                 ; blocks (read them with STATUS)
    !byte $bf               ; status byte
    !byte <driver5
