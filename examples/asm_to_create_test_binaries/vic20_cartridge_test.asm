; A VIC-20 cartridge for commodore.is_cartridge() with commodore.vic20() (see
; python/vic20_cartridge_test.py): the header at $a000 with its cold and warm
; start vectors and 'A0CBM' signature, and code that initialises the machine,
; sets the NMI vector and polls the keyboard. Assemble with:
;
;   acme -o ../orig/vic20_cartridge_test.orig vic20_cartridge_test.asm

    * = $a000

    !word cold_start
    !word warm_start
    !pet "a0CBM"

cold_start
    jsr $fd8d               ; RAMTAS
    jsr $fd52               ; RESTOR
    jsr $fdf9               ; IOINIT
    jsr $e518               ; CINT
    ldx #<nmi
    ldy #>nmi
    stx $0318
    sty $0319
wait
    jsr $ffe4               ; GETIN
    beq wait
warm_start
    jmp ($c002)

nmi
    rti
