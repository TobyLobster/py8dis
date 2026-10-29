; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070

; OS vectors ($0200-$0235)
userv   = $0200
brkv    = $0202
irq2v   = $0206
cliv    = $0208
bytev   = $020a
wordv   = $020c
wrchv   = $020e
rdchv   = $0210
filev   = $0212
evntv   = $0220

    * = $2000

pydis_start
start
    ; Set IRQ 2 vector to 'handle_irq2v'
    ldx #<handle_irq2v                                                ; 2000: a2 74       .t
    stx irq2v                                                         ; 2002: 8e 06 02    ...
    ldx #>handle_irq2v                                                ; 2005: a2 20       .
    stx irq2v+1                                                       ; 2007: 8e 07 02    ...

    ; Set write character vector to 'handle_wrchv'
    ldy #>handle_wrchv                                                ; 200a: a0 20       .
    sty wrchv+1                                                       ; 200c: 8c 0f 02    ...
    ldy #<handle_wrchv                                                ; 200f: a0 75       .u
    sty wrchv                                                         ; 2011: 8c 0e 02    ...

    ; Set read character vector to 'handle_rdchv'
    ldx #<handle_rdchv                                                ; 2014: a2 76       .v
    ldy #>handle_rdchv                                                ; 2016: a0 20       .
    stx rdchv                                                         ; 2018: 8e 10 02    ...
    sty rdchv+1                                                       ; 201b: 8c 11 02    ...

    ; Set osbyte vector to 'handle_bytev'
    lda #<handle_bytev                                                ; 201e: a9 77       .w
    ldx #>handle_bytev                                                ; 2020: a2 20       .
    stx bytev+1                                                       ; 2022: 8e 0b 02    ...
    sta bytev                                                         ; 2025: 8d 0a 02    ...

    ; Set event vector to 'handle_evntv'
    lda #<handle_evntv                                                ; 2028: a9 78       .x
    ldx #>handle_evntv                                                ; 202a: a2 20       .
    sei                                                               ; 202c: 78          x
    sta evntv                                                         ; 202d: 8d 20 02    . .
    stx evntv+1                                                       ; 2030: 8e 21 02    .!.

    cli                                                               ; 2033: 58          X

    ; Set osword vector to 'handle_wordv'
    lda #<handle_wordv                                                ; 2034: a9 79       .y
    sta wordv                                                         ; 2036: 8d 0c 02    ...
    ; Set command line interpreter vector to 'handle_cliv'
    lda #<handle_cliv                                                 ; 2039: a9 7a       .z
    sta cliv                                                          ; 203b: 8d 08 02    ...
    lda #>handle_wordv                                                ; 203e: a9 20       .
    sta wordv+1                                                       ; 2040: 8d 0d 02    ...
    sta cliv+1                                                        ; 2043: 8d 09 02    ...

    ; Set user vector to 'handle_userv'
    ldx #<handle_userv                                                ; 2046: a2 7b       .{
    txa                                                               ; 2048: 8a          .  ; A=$7b
    sta userv                                                         ; 2049: 8d 00 02    ...
    lda #>handle_userv                                                ; 204c: a9 20       .
    sta userv+1                                                       ; 204e: 8d 01 02    ...

    ; Set BRK vector to 'handle_brkv'
    lda #<handle_brkv                                                 ; 2051: a9 7c       .|
    ldx #>handle_brkv                                                 ; 2053: a2 20       .
    ldy #0                                                            ; 2055: a0 00       ..
    sta brkv                                                          ; 2057: 8d 02 02    ...
    stx brkv+1                                                        ; 205a: 8e 03 02    ...

    sty l0070                                                         ; 205d: 84 70       .p
    lda #0                                                            ; 205f: a9 00       ..
    ldx #$20 ; ' '                                                    ; 2061: a2 20       .
    sta irq2v                                                         ; 2063: 8d 06 02    ... ; Set the low byte of IRQ 2 vector to $00
    stx cliv+1                                                        ; 2066: 8e 09 02    ... ; Set the high byte of command line interpreter vector to $20
    lda #0                                                            ; 2069: a9 00       ..
    sta filev                                                         ; 206b: 8d 12 02    ... ; Set the low byte of load/save file vector to $00 (and the high byte to a value that isn't known)
    lda l0070                                                         ; 206e: a5 70       .p
    sta filev+1                                                       ; 2070: 8d 13 02    ...
    rts                                                               ; 2073: 60          `

handle_irq2v
    rti                                                               ; 2074: 40          @

handle_wrchv
    rts                                                               ; 2075: 60          `

handle_rdchv
    rts                                                               ; 2076: 60          `

handle_bytev
    rts                                                               ; 2077: 60          `

handle_evntv
    rts                                                               ; 2078: 60          `

handle_wordv
    rts                                                               ; 2079: 60          `

handle_cliv
    rts                                                               ; 207a: 60          `

handle_userv
    rts                                                               ; 207b: 60          `

handle_brkv
    rti                                                               ; 207c: 40          @

pydis_end

.cerror (<handle_brkv) != $7c, "Assertion failed: <handle_brkv == $7c"
.cerror (<handle_bytev) != $77, "Assertion failed: <handle_bytev == $77"
.cerror (<handle_cliv) != $7a, "Assertion failed: <handle_cliv == $7a"
.cerror (<handle_evntv) != $78, "Assertion failed: <handle_evntv == $78"
.cerror (<handle_irq2v) != $74, "Assertion failed: <handle_irq2v == $74"
.cerror (<handle_rdchv) != $76, "Assertion failed: <handle_rdchv == $76"
.cerror (<handle_userv) != $7b, "Assertion failed: <handle_userv == $7b"
.cerror (<handle_wordv) != $79, "Assertion failed: <handle_wordv == $79"
.cerror (<handle_wrchv) != $75, "Assertion failed: <handle_wrchv == $75"
.cerror (>handle_brkv) != $20, "Assertion failed: >handle_brkv == $20"
.cerror (>handle_bytev) != $20, "Assertion failed: >handle_bytev == $20"
.cerror (>handle_evntv) != $20, "Assertion failed: >handle_evntv == $20"
.cerror (>handle_irq2v) != $20, "Assertion failed: >handle_irq2v == $20"
.cerror (>handle_rdchv) != $20, "Assertion failed: >handle_rdchv == $20"
.cerror (>handle_userv) != $20, "Assertion failed: >handle_userv == $20"
.cerror (>handle_wordv) != $20, "Assertion failed: >handle_wordv == $20"
.cerror (>handle_wrchv) != $20, "Assertion failed: >handle_wrchv == $20"

; Label references by decreasing frequency:
;     irq2v:   2
;     l0070:   2
;     brkv:    1
;     bytev:   1
;     cliv:    1
;     evntv:   1
;     filev:   1
;     rdchv:   1
;     userv:   1
;     wordv:   1
;     wrchv:   1

; Automatically generated labels:
;     l0070

; Stats:
;
;     Total size (Code + Data) = 125 bytes
;     Code                     = 125 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 58
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

