; Memory locations

; Vectors ($0300-$0333)
irq_vector      = $0314
brk_vector      = $0316
nmi_vector      = $0318
chrout_vector   = $0326

; BASIC ROM ($a000-$bfff)
basic_warm_start_vector = $a002

; VIC-II ($d000-$d3ff)
vic_border_colour   = $d020

; Kernal ROM ($e000-$ff80)
kernal_irq_handler  = $ea31
NBSOUT              = $f1ca
RESTOR_ROM          = $fd15
RAMTAS_ROM          = $fd50
IOINIT_ROM          = $fda3
PCINT               = $ff5b

; Kernal entry points ($ff81-$fff9)
GETIN   = $ffe4

    * = $8000

; Cartridge header
pydis_start
cartridge_cold_start_vector
    !word cartridge_cold_start                                        ; 8000: 09 80       ..
cartridge_warm_start_vector
    !word cartridge_warm_start                                        ; 8002: 48 80       h.
cartridge_signature
    !pet "CBM80"                                                      ; 8004: c3 c2 cd... CBM

cartridge_cold_start
    sei                                                               ; 8009: 78          .
    jsr IOINIT_ROM                                                    ; 800a: 20 a3 fd     ..
    jsr RAMTAS_ROM                                                    ; 800d: 20 50 fd     p.
    jsr RESTOR_ROM                                                    ; 8010: 20 15 fd     ..
    jsr PCINT                                                         ; 8013: 20 5b ff     [.

    ; Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 ; 8016: a2 4b       .k
    ldy #>nmi_handler                                                 ; 8018: a0 80       ..
    stx nmi_vector                                                    ; 801a: 8e 18 03    ...
    sty nmi_vector+1                                                  ; 801d: 8c 19 03    ...

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 8020: a9 50       .p
    ldx #>irq_handler                                                 ; 8022: a2 80       ..
    sta irq_vector                                                    ; 8024: 8d 14 03    ...
    stx irq_vector+1                                                  ; 8027: 8e 15 03    ...

    ; Set the BRK vector to brk_handler
    ldy #<brk_handler                                                 ; 802a: a0 4c       .l
    sty brk_vector                                                    ; 802c: 8c 16 03    ...
    ldy #>brk_handler                                                 ; 802f: a0 80       ..
    sty brk_vector+1                                                  ; 8031: 8c 17 03    ...

    ; Set the CHROUT vector to chrout_handler
    ldx #<chrout_handler                                              ; 8034: a2 4d       .m
    lda #>chrout_handler                                              ; 8036: a9 80       ..
    sta chrout_vector+1                                               ; 8038: 8d 27 03    .'.
    stx chrout_vector                                                 ; 803b: 8e 26 03    .&.

    cli                                                               ; 803e: 58          x
; $803f referenced 2 times by $8042, $8046
c803f
    jsr GETIN                                                         ; 803f: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq c803f                                                         ; 8042: f0 fb       ..
    cmp #$51 ; 'q'                                                    ; 8044: c9 51       Iq ; A=character read
    bne c803f                                                         ; 8046: d0 f7       P.
cartridge_warm_start
    jmp (basic_warm_start_vector)                                     ; 8048: 6c 02 a0    ...

nmi_handler
    rti                                                               ; 804b: 40          @

brk_handler
    rti                                                               ; 804c: 40          @

chrout_handler
    jmp NBSOUT                                                        ; 804d: 4c ca f1    lJ.

irq_handler
    inc vic_border_colour                                             ; 8050: ee 20 d0    . P
    jmp kernal_irq_handler                                            ; 8053: 4c 31 ea    l1. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

pydis_end

!if (<brk_handler) != $4c {
    !error "Assertion failed: <brk_handler == $4c"
}
!if (<chrout_handler) != $4d {
    !error "Assertion failed: <chrout_handler == $4d"
}
!if (<irq_handler) != $50 {
    !error "Assertion failed: <irq_handler == $50"
}
!if (<nmi_handler) != $4b {
    !error "Assertion failed: <nmi_handler == $4b"
}
!if (>brk_handler) != $80 {
    !error "Assertion failed: >brk_handler == $80"
}
!if (>chrout_handler) != $80 {
    !error "Assertion failed: >chrout_handler == $80"
}
!if (>irq_handler) != $80 {
    !error "Assertion failed: >irq_handler == $80"
}
!if (>nmi_handler) != $80 {
    !error "Assertion failed: >nmi_handler == $80"
}
!if (cartridge_cold_start) != $8009 {
    !error "Assertion failed: cartridge_cold_start == $8009"
}
!if (cartridge_warm_start) != $8048 {
    !error "Assertion failed: cartridge_warm_start == $8048"
}

; Label references by decreasing frequency:
;     c803f:                     2
;     GETIN:                     1
;     IOINIT_ROM:                1
;     NBSOUT:                    1
;     PCINT:                     1
;     RAMTAS_ROM:                1
;     RESTOR_ROM:                1
;     basic_warm_start_vector:   1
;     brk_vector:                1
;     chrout_vector:             1
;     irq_vector:                1
;     kernal_irq_handler:        1
;     nmi_vector:                1
;     vic_border_colour:         1

; Automatically generated labels:
;     c803f

; Stats:
;
;     Total size (Code + Data) = 86 bytes
;     Code                     = 77 bytes (90%)
;     Data                     = 9 bytes (10%)
;
;     Number of instructions   = 32
;     Number of data bytes     = 0 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1

