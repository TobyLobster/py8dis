; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Constants
mode_3  = 3
mode_7  = 7

; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071

; Other
l0300   = $0300
l0301   = $0301
l0302   = $0302
l0303   = $0303

    .org $2000

pydis_start:
start:
    lda #<handler_209f                                                ; 2000: a9 9f       ..
    ldx #>handler_209f                                                ; 2002: a2 20       .
    sei                                                               ; 2004: 78          x
    ; Set the vector at $0300 to handler_209f
    stx l0301                                                         ; 2005: 8e 01 03    ...
    sta l0300                                                         ; 2008: 8d 00 03    ...
    cli                                                               ; 200b: 58          X
    lda #<handler_20a0                                                ; 200c: a9 a0       ..
    ; Set the vector at $0302 to handler_20a0
    sta l0302                                                         ; 200e: 8d 02 03    ...
    lda #>handler_20a0                                                ; 2011: a9 20       .
    sta l0303                                                         ; 2013: 8d 03 03    ...
    lda #<handler_20a1                                                ; 2016: a9 a1       ..
    ; Set the vector at $0302 to handler_20a1
    sta l0302                                                         ; 2018: 8d 02 03    ...
    lda #>handler_20a1                                                ; 201b: a9 20       .
    sta l0303                                                         ; 201d: 8d 03 03    ...
    lda #$12                                                          ; 2020: a9 12       ..
    ; Set the low byte of the vector at $0300 to $12
    sta l0300                                                         ; 2022: 8d 00 03    ...
    jsr subroutine                                                    ; 2025: 20 9c 20     .
    lda #$34 ; '4'                                                    ; 2028: a9 34       .4
    ; Set the low byte of the vector at $0302 to $34 (the high byte isn't known)
    sta l0302                                                         ; 202a: 8d 02 03    ...
    lda l0070                                                         ; 202d: a5 70       .p
    sta l0303                                                         ; 202f: 8d 03 03    ...
    ldx #<handler_20a2                                                ; 2032: a2 a2       ..
    txa                                                               ; 2034: 8a          .  ; A=$a2
    ; Set the vector at $0300 to handler_20a2
    sta l0300                                                         ; 2035: 8d 00 03    ...
    lda #>handler_20a2                                                ; 2038: a9 20       .
    sta l0301                                                         ; 203a: 8d 01 03    ...
    lda #3                                                            ; 203d: a9 03       ..
    sta l0070                                                         ; 203f: 85 70       .p
    ldx #5                                                            ; 2041: a2 05       ..
    jsr print                                                         ; 2043: 20 9d 20     . ; Print with 3 at &70, X=5
    lda #3                                                            ; 2046: a9 03       ..
    sta l0070                                                         ; 2048: 85 70       .p
    ldx #6                                                            ; 204a: a2 06       ..
    jsr print                                                         ; 204c: 20 9d 20     .
    lda l0071                                                         ; 204f: a5 71       .q
    sta l0070                                                         ; 2051: 85 70       .p
    ldx #5                                                            ; 2053: a2 05       ..
    jsr print                                                         ; 2055: 20 9d 20     .
    lda #7                                                            ; 2058: a9 07       ..
    sta l0070                                                         ; 205a: 85 70       .p
    lda l0071                                                         ; 205c: a5 71       .q
    sta l0071                                                         ; 205e: 85 71       .q
    ldx #5                                                            ; 2060: a2 05       ..
    jsr print                                                         ; 2062: 20 9d 20     . ; Print with 7 at &70, X=5, and something at &71
    lda #$a3                                                          ; 2065: a9 a3       ..
    ; Set the low byte of the vector at $0302 to $a3
    sta l0302                                                         ; 2067: 8d 02 03    ...
    bne c206c                                                         ; 206a: d0 00       .. ; ALWAYS branch

; $206c referenced 1 time by $206a
c206c:
    lda #$20 ; ' '                                                    ; 206c: a9 20       .
    ; Set the high byte of the vector at $0302 to $20
    sta l0303                                                         ; 206e: 8d 03 03    ...
    ; Select mode 7
    lda #$16                                                          ; 2071: a9 16       ..
    jsr write                                                         ; 2073: 20 9e 20     .
    lda #mode_7                                                       ; 2076: a9 07       ..
    jsr write                                                         ; 2078: 20 9e 20     .
    ; Select mode 3
    ldx #$16                                                          ; 207b: a2 16       ..
    txa                                                               ; 207d: 8a          .  ; A=$16
    jsr write                                                         ; 207e: 20 9e 20     .
    ldy #mode_3                                                       ; 2081: a0 03       ..
    tya                                                               ; 2083: 98          .  ; A=3
    jsr write                                                         ; 2084: 20 9e 20     .
    lda #$17                                                          ; 2087: a9 17       ..
    jsr write                                                         ; 2089: 20 9e 20     .
    lda #7                                                            ; 208c: a9 07       ..
    jsr write                                                         ; 208e: 20 9e 20     .
    lda #$16                                                          ; 2091: a9 16       ..
    jsr write                                                         ; 2093: 20 9e 20     .
    lda l0070                                                         ; 2096: a5 70       .p
    jsr write                                                         ; 2098: 20 9e 20     .
    rts                                                               ; 209b: 60          `

; $209c referenced 1 time by $2025
subroutine:
    rts                                                               ; 209c: 60          `

; $209d referenced 4 times by $2043, $204c, $2055, $2062
print:
    rts                                                               ; 209d: 60          `

; $209e referenced 8 times by $2073, $2078, $207e, $2084, $2089, $208e, $2093, $2098
write:
    rts                                                               ; 209e: 60          `

handler_209f:
    rti                                                               ; 209f: 40          @

handler_20a0:
    rti                                                               ; 20a0: 40          @

handler_20a1:
    rti                                                               ; 20a1: 40          @

handler_20a2:
    rti                                                               ; 20a2: 40          @

    .byte $40                                                         ; 20a3: 40          @
pydis_end:

.assert (<handler_209f) = $9f, error, "Assertion failed: <handler_209f = $9f"
.assert (<handler_20a0) = $a0, error, "Assertion failed: <handler_20a0 = $a0"
.assert (<handler_20a1) = $a1, error, "Assertion failed: <handler_20a1 = $a1"
.assert (<handler_20a2) = $a2, error, "Assertion failed: <handler_20a2 = $a2"
.assert (>handler_209f) = $20, error, "Assertion failed: >handler_209f = $20"
.assert (>handler_20a0) = $20, error, "Assertion failed: >handler_20a0 = $20"
.assert (>handler_20a1) = $20, error, "Assertion failed: >handler_20a1 = $20"
.assert (>handler_20a2) = $20, error, "Assertion failed: >handler_20a2 = $20"

; Label references by decreasing frequency:
;     write:        8
;     l0070:        6
;     l0302:        4
;     l0303:        4
;     print:        4
;     l0071:        3
;     l0300:        3
;     l0301:        2
;     c206c:        1
;     subroutine:   1

; Automatically generated labels:
;     c206c
;     l0070
;     l0071
;     l0300
;     l0301
;     l0302
;     l0303

; Stats:
;
;     Total size (Code + Data) = 164 bytes
;     Code                     = 163 bytes (99%)
;     Data                     = 1 bytes (1%)
;
;     Number of instructions   = 75
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

