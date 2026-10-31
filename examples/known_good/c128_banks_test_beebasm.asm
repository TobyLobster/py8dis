; Constants
colour_black    = 0

; Memory locations

; Zero page (&0000-&00ff)
l00fb   = &00fb
l00fc   = &00fc

; OS workspace (&0200-&03ff)
basic_error_vector  = &0300

; Screen memory (&0400-&07ff)
screen_memory   = &0400

; BASIC ROM (&4000-&afff)
l4000   = &4000

; VIC-II (&d000-&d3ff)
vic_interrupt_status    = &d019
vic_border_colour       = &d020
vic_background_colour_0 = &d021

; MMU (&d500-&d5ff)
mmu_configuration_io = &d500

; MMU (&ff00-&ff04)
mmu_configuration       = &ff00
mmu_load_configuration_a = &ff01

; Kernal entry points (&ff47-&fff9)
PRIMM   = &ff7d
CHROUT  = &ffd2

; Other banks
l1000   = &1000
ld000   = &d000
ld019   = &d019
ld020   = &d020
le000   = &e000
lff7d   = &ff7d
lffd2   = &ffd2

; The PRG file's header: the address to load it at
    org &1bff
    equw &1c01

    org &1c01

; 10 SYS7181
.pydis_start
.basic_line_10
    equw basic_end                                                    ; 1c01: 0b 1c       ..
    equw 10                                                           ; 1c03: 0a 00       ..
    equb &9e                                                          ; 1c05: 9e          .
    equb &37, &31, &38, &31 ; petscii "7181"                          ; 1c06: 37 31 38... 718
    equb 0                                                            ; 1c0a: 00          .
.basic_end
    equw 0                                                            ; 1c0b: 00 00       ..

.sys_entry
    lda #colour_black                                                 ; 1c0d: a9 00       ..
    sta mmu_configuration                                             ; 1c0f: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    sta vic_border_colour                                             ; 1c12: 8d 20 d0    . P
    lda #&3e ; '>'                                                    ; 1c15: a9 3e       .>
    sta mmu_configuration                                             ; 1c17: 8d 00 ff    ... ; Set the MMU to RAM 0, I/O
    sta vic_background_colour_0                                       ; 1c1a: 8d 21 d0    .!P
    lda le000                                                         ; 1c1d: ad 00 e0    ...
    sta l00fb                                                         ; 1c20: 85 fb       ..
    lda #&3f ; '?'                                                    ; 1c22: a9 3f       .?
    sta mmu_configuration                                             ; 1c24: 8d 00 ff    ... ; Set the MMU to bank 0 (RAM 0 only)
    lda ld020                                                         ; 1c27: ad 20 d0    . P
    sta l00fc                                                         ; 1c2a: 85 fc       ..
    lda #&41 ; 'a'                                                    ; 1c2c: a9 41       .a
    jsr lffd2                                                         ; 1c2e: 20 d2 ff     R.
    lda #0                                                            ; 1c31: a9 00       ..
    sta mmu_configuration                                             ; 1c33: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    ldx #&7f                                                          ; 1c36: a2 7f       ..
    stx mmu_configuration_io                                          ; 1c38: 8e 00 d5    ..U ; Set the MMU to bank 1 (RAM 1 only)
    lda l1000                                                         ; 1c3b: ad 00 10    ...
    sta basic_error_vector                                            ; 1c3e: 8d 00 03    ...
    sta mmu_load_configuration_a                                      ; 1c41: 8d 01 ff    ... ; Set the MMU to preconfiguration A (as set at $d501)
    lda vic_border_colour                                             ; 1c44: ad 20 d0    . P
    lda #0                                                            ; 1c47: a9 00       ..
    sta mmu_configuration                                             ; 1c49: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    jsr sub_c1c5f                                                     ; 1c4c: 20 5f 1c     ..
    lda vic_border_colour                                             ; 1c4f: ad 20 d0    . P
    lda #&41 ; 'a'                                                    ; 1c52: a9 41       .a ; A=character to output
    jsr CHROUT                                                        ; 1c54: 20 d2 ff     R. ; Output 'a'
    lda #1                                                            ; 1c57: a9 01       ..
    sta vic_interrupt_status                                          ; 1c59: 8d 19 d0    ..P ; Acknowledge the VIC-II's raster interrupt
    jmp c1c76                                                         ; 1c5c: 4c 76 1c    l..

; &1c5f referenced 1 time by &1c4c
.sub_c1c5f
    ldx #0                                                            ; 1c5f: a2 00       ..
; &1c61 referenced 1 time by &1c68
.loop_c1c61
    lda ld000,x                                                       ; 1c61: bd 00 d0    ..P
    sta l4000,x                                                       ; 1c64: 9d 00 40    ..@
    inx                                                               ; 1c67: e8          .
    bne loop_c1c61                                                    ; 1c68: d0 f7       P.
    lda #1                                                            ; 1c6a: a9 01       ..
    sta ld020                                                         ; 1c6c: 8d 20 d0    . P
    sta ld019                                                         ; 1c6f: 8d 19 d0    ..P
    jsr lff7d                                                         ; 1c72: 20 7d ff     ..
    rts                                                               ; 1c75: 60          .

; &1c76 referenced 1 time by &1c5c
.c1c76
    lda #&3f ; '?'                                                    ; 1c76: a9 3f       .?
    sta mmu_configuration                                             ; 1c78: 8d 00 ff    ... ; Set the MMU to bank 0 (RAM 0 only)
    ldx #0                                                            ; 1c7b: a2 00       ..
; &1c7d referenced 1 time by &1c84
.loop_c1c7d
    lda ld000,x                                                       ; 1c7d: bd 00 d0    ..P
    sta screen_memory,x                                               ; 1c80: 9d 00 04    ...
    inx                                                               ; 1c83: e8          .
    bne loop_c1c7d                                                    ; 1c84: d0 f7       P.
    jsr sub_c1cbe                                                     ; 1c86: 20 be 1c     ..
    lda #0                                                            ; 1c89: a9 00       ..
    sta mmu_configuration                                             ; 1c8b: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    jsr sub_c1cc2                                                     ; 1c8e: 20 c2 1c     B.
    lda #&3f ; '?'                                                    ; 1c91: a9 3f       .?
    sta mmu_configuration                                             ; 1c93: 8d 00 ff    ... ; Set the MMU to bank 0 (RAM 0 only)
    jsr sub_c1cc2                                                     ; 1c96: 20 c2 1c     B.
    lda #0                                                            ; 1c99: a9 00       ..
    sta mmu_configuration                                             ; 1c9b: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    jsr sub_c1cb8                                                     ; 1c9e: 20 b8 1c     ..
    lda ld020                                                         ; 1ca1: ad 20 d0    . P
    lda #1                                                            ; 1ca4: a9 01       ..
    sta mmu_configuration                                             ; 1ca6: 8d 00 ff    ... ; Set the MMU to bank 14 (RAM 0, BASIC ROM, Kernal ROM, character ROM)
    jsr PRIMM                                                         ; 1ca9: 20 7d ff     .. ; Print the zero-terminated string that follows the JSR
    equb &48, &49, 0 ; petscii "hi", &00                              ; 1cac: 48 49 00    hi.

    lda ld020                                                         ; 1caf: ad 20 d0    . P
    lda #0                                                            ; 1cb2: a9 00       ..
    sta mmu_configuration                                             ; 1cb4: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    rts                                                               ; 1cb7: 60          .

; &1cb8 referenced 1 time by &1c9e
.sub_c1cb8
    lda #&3f ; '?'                                                    ; 1cb8: a9 3f       .?
    sta mmu_configuration                                             ; 1cba: 8d 00 ff    ... ; Set the MMU to bank 0 (RAM 0 only)
    rts                                                               ; 1cbd: 60          .

; &1cbe referenced 1 time by &1c86
.sub_c1cbe
    inc ld020                                                         ; 1cbe: ee 20 d0    . P
    rts                                                               ; 1cc1: 60          .

; &1cc2 referenced 2 times by &1c8e, &1c96
.sub_c1cc2
    inc vic_background_colour_0                                       ; 1cc2: ee 21 d0    .!P
    rts                                                               ; 1cc5: 60          .

.pydis_end

    assert &1c0b == basic_end

save pydis_start - 2, pydis_end

; Label references by decreasing frequency:
;     mmu_configuration:         12
;     ld020:                      8
;     vic_border_colour:          8
;     CHROUT:                     2
;     PRIMM:                      2
;     ld000:                      2
;     ld019:                      2
;     lff7d:                      2
;     lffd2:                      2
;     sub_c1cc2:                  2
;     vic_background_colour_0:    2
;     vic_interrupt_status:       2
;     basic_error_vector:         1
;     c1c76:                      1
;     l00fb:                      1
;     l00fc:                      1
;     l1000:                      1
;     l4000:                      1
;     le000:                      1
;     loop_c1c61:                 1
;     loop_c1c7d:                 1
;     mmu_configuration_io:       1
;     mmu_load_configuration_a:   1
;     screen_memory:              1
;     sub_c1c5f:                  1
;     sub_c1cb8:                  1
;     sub_c1cbe:                  1

; Automatically generated labels:
;     c1c76
;     l00fb
;     l00fc
;     l4000
;     loop_c1c61
;     loop_c1c7d
;     sub_c1c5f
;     sub_c1cb8
;     sub_c1cbe
;     sub_c1cc2

; Stats:
;
;     Total size (Code + Data) = 197 bytes
;     Code                     = 182 bytes (92%)
;     Data                     = 15 bytes (8%)
;
;     Number of instructions   = 73
;     Number of data bytes     = 2 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 7 bytes
;     Number of strings        = 2

