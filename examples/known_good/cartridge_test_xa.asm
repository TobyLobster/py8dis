// Memory locations

// Vectors ($0300-$0333)
irq_vector  = $0314
nmi_vector  = $0318

// BASIC ROM ($a000-$bfff)
basic_warm_start_vector = $a002

// VIC-II ($d000-$d3ff)
vic_border_colour   = $d020

// Kernal ROM ($e000-$ff80)
kernal_irq_handler  = $ea31
restor_rom          = $fd15
ramtas_rom          = $fd50
ioinit_rom          = $fda3
lff5b               = $ff5b

// Kernal entry points ($ff81-$fff9)
getin   = $ffe4

    * = $8000

// Cartridge header
pydis_start
cartridge_cold_start_vector
    .word cartridge_cold_start                                        // 8000: 09 80       ..
cartridge_warm_start_vector
    .word cartridge_warm_start                                        // 8002: 34 80       4.
cartridge_signature
    .byt $c3, $c2, $cd, $38, $30 // petscii "CBM80"                   // 8004: c3 c2 cd... CBM

cartridge_cold_start
    sei                                                               // 8009: 78          .
    jsr ioinit_rom                                                    // 800a: 20 a3 fd     ..
    jsr ramtas_rom                                                    // 800d: 20 50 fd     p.
    jsr restor_rom                                                    // 8010: 20 15 fd     ..
    jsr lff5b                                                         // 8013: 20 5b ff     [.

    // Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 // 8016: a2 37       .7
    ldy #>nmi_handler                                                 // 8018: a0 80       ..
    stx nmi_vector                                                    // 801a: 8e 18 03    ...
    sty nmi_vector+1                                                  // 801d: 8c 19 03    ...

    // Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 // 8020: a9 38       .8
    ldx #>irq_handler                                                 // 8022: a2 80       ..
    sta irq_vector                                                    // 8024: 8d 14 03    ...
    stx irq_vector+1                                                  // 8027: 8e 15 03    ...

    cli                                                               // 802a: 58          x
// $802b referenced 2 times by $802e, $8032
c802b
    jsr getin                                                         // 802b: 20 e4 ff     .. // Get a character from the input channel (from the keyboard, 0 if there's none)
    beq c802b                                                         // 802e: f0 fb       ..
    cmp #$51 // 'q'                                                   // 8030: c9 51       Iq // A=character read
    bne c802b                                                         // 8032: d0 f7       P.
cartridge_warm_start
    jmp (basic_warm_start_vector)                                     // 8034: 6c 02 a0    ...

nmi_handler
    rti                                                               // 8037: 40          @

irq_handler
    inc vic_border_colour                                             // 8038: ee 20 d0    . P
    jmp kernal_irq_handler                                            // 803b: 4c 31 ea    l1. // The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

pydis_end

#if ((irq_handler) & $ff) <> $38
#error Assertion failed: <irq_handler == $38
#endif
#if ((nmi_handler) & $ff) <> $37
#error Assertion failed: <nmi_handler == $37
#endif
#if (((irq_handler) >> 8) & $ff) <> $80
#error Assertion failed: >irq_handler == $80
#endif
#if (((nmi_handler) >> 8) & $ff) <> $80
#error Assertion failed: >nmi_handler == $80
#endif
#if (cartridge_cold_start) <> $8009
#error Assertion failed: cartridge_cold_start == $8009
#endif
#if (cartridge_warm_start) <> $8034
#error Assertion failed: cartridge_warm_start == $8034
#endif

// Label references by decreasing frequency:
//     c802b:                     2
//     basic_warm_start_vector:   1
//     getin:                     1
//     ioinit_rom:                1
//     irq_vector:                1
//     kernal_irq_handler:        1
//     lff5b:                     1
//     nmi_vector:                1
//     ramtas_rom:                1
//     restor_rom:                1
//     vic_border_colour:         1

// Automatically generated labels:
//     c802b
//     lff5b

// Stats:
//
//     Total size (Code + Data) = 62 bytes
//     Code                     = 53 bytes (85%)
//     Data                     = 9 bytes (15%)
//
//     Number of instructions   = 22
//     Number of data bytes     = 0 bytes
//     Number of data words     = 4 bytes
//     Number of string bytes   = 5 bytes
//     Number of strings        = 1

