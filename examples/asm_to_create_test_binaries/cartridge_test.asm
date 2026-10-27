; A C64 cartridge for commodore.is_cartridge() (see python/cartridge_test.py):
; the header with its cold and warm start vectors and 'CBM80' signature, and
; code that initialises the machine, sets the NMI and IRQ vectors (in the two
; other ways commodore.c64() recognises) and polls the keyboard. Assemble with:
;
;   acme -o ../orig/cartridge_test.orig cartridge_test.asm

    * = $8000

    !word cold_start
    !word warm_start
    !pet "CBM80"

cold_start
    sei
    jsr $fda3               ; IOINIT
    jsr $fd50               ; RAMTAS
    jsr $fd15               ; RESTOR
    jsr $ff5b               ; CINT
    ldx #<nmi
    ldy #>nmi
    stx $0318
    sty $0319
    lda #<irq
    ldx #>irq
    sta $0314
    stx $0315
    cli
wait
    jsr $ffe4               ; GETIN
    beq wait
    cmp #'Q'
    bne wait
warm_start
    jmp ($a002)

nmi
    rti

irq
    inc $d020
    jmp $ea31
