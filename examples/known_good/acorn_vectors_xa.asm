// Memory locations

// OS vectors ($0200-$0235)
irq2v   = $0206
cliv    = $0208
bytev   = $020a
wrchv   = $020e
rdchv   = $0210

    * = $2000

pydis_start
start
    // Set IRQ 2 vector to 'handle_irq2v'
    ldx #<handle_irq2v                                                // 2000: a2 33       .3
    stx irq2v                                                         // 2002: 8e 06 02    ...
    ldx #>handle_irq2v                                                // 2005: a2 20       .
    stx irq2v+1                                                       // 2007: 8e 07 02    ...

    // Set write character vector to 'handle_wrchv'
    ldy #>handle_wrchv                                                // 200a: a0 20       .
    sty wrchv+1                                                       // 200c: 8c 0f 02    ...
    ldy #<handle_wrchv                                                // 200f: a0 34       .4
    sty wrchv                                                         // 2011: 8c 0e 02    ...

    // Set read character vector to 'handle_rdchv'
    ldx #<handle_rdchv                                                // 2014: a2 35       .5
    ldy #>handle_rdchv                                                // 2016: a0 20       .
    stx rdchv                                                         // 2018: 8e 10 02    ...
    sty rdchv+1                                                       // 201b: 8c 11 02    ...

    // Set osbyte vector to 'handle_bytev'
    lda #<handle_bytev                                                // 201e: a9 36       .6
    ldx #>handle_bytev                                                // 2020: a2 20       .
    stx bytev+1                                                       // 2022: 8e 0b 02    ...
    sta bytev                                                         // 2025: 8d 0a 02    ...

    lda #0                                                            // 2028: a9 00       ..
    ldx #$20 // ' '                                                   // 202a: a2 20       .
    sta irq2v                                                         // 202c: 8d 06 02    ...
    stx cliv+1                                                        // 202f: 8e 09 02    ...
    rts                                                               // 2032: 60          `

handle_irq2v
    rti                                                               // 2033: 40          @

handle_wrchv
    rts                                                               // 2034: 60          `

handle_rdchv
    rts                                                               // 2035: 60          `

handle_bytev
    rts                                                               // 2036: 60          `

pydis_end

#if ((handle_bytev) & $ff) <> $36
#error Assertion failed: <handle_bytev == $36
#endif
#if ((handle_irq2v) & $ff) <> $33
#error Assertion failed: <handle_irq2v == $33
#endif
#if ((handle_rdchv) & $ff) <> $35
#error Assertion failed: <handle_rdchv == $35
#endif
#if ((handle_wrchv) & $ff) <> $34
#error Assertion failed: <handle_wrchv == $34
#endif
#if (((handle_bytev) >> 8) & $ff) <> $20
#error Assertion failed: >handle_bytev == $20
#endif
#if (((handle_irq2v) >> 8) & $ff) <> $20
#error Assertion failed: >handle_irq2v == $20
#endif
#if (((handle_rdchv) >> 8) & $ff) <> $20
#error Assertion failed: >handle_rdchv == $20
#endif
#if (((handle_wrchv) >> 8) & $ff) <> $20
#error Assertion failed: >handle_wrchv == $20
#endif

// Label references by decreasing frequency:
//     irq2v:   2
//     bytev:   1
//     rdchv:   1
//     wrchv:   1

// Stats:
//
//     Total size (Code + Data) = 55 bytes
//     Code                     = 55 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 25
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

