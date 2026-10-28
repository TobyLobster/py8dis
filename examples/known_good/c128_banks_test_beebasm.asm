; Constants
colour_black    = 0

; Memory locations

; Zero page (&0000-&00ff)
l00fb   = &00fb
l00fc   = &00fc

; OS workspace (&0200-&03ff)
basic_error_vector  = &0300

; Function keys (&1000-&10ff)
l1000   = &1000

; BASIC ROM (&4000-&afff)
l4000   = &4000

; VIC-II (&d000-&d3ff)
ld000                   = &d000
vic_border_colour       = &d020
ld020                   = &d020
vic_background_colour_0 = &d021

; MMU (&d500-&d5ff)
mmu_configuration_io = &d500

; Kernal ROM (&e000-&feff)
le000   = &e000

; MMU (&ff00-&ff04)
mmu_configuration       = &ff00
mmu_load_configuration_a = &ff01

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
    lda #0                                                            ; 1c2c: a9 00       ..
    sta mmu_configuration                                             ; 1c2e: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    ldx #&7f                                                          ; 1c31: a2 7f       ..
    stx mmu_configuration_io                                          ; 1c33: 8e 00 d5    ..U ; Set the MMU to bank 1 (RAM 1 only)
    lda l1000                                                         ; 1c36: ad 00 10    ...
    sta basic_error_vector                                            ; 1c39: 8d 00 03    ...
    sta mmu_load_configuration_a                                      ; 1c3c: 8d 01 ff    ... ; Set the MMU to preconfiguration A (as set at $d501)
    lda vic_border_colour                                             ; 1c3f: ad 20 d0    . P
    lda #0                                                            ; 1c42: a9 00       ..
    sta mmu_configuration                                             ; 1c44: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    jsr sub_c1c4e                                                     ; 1c47: 20 4e 1c     n.
    lda vic_border_colour                                             ; 1c4a: ad 20 d0    . P
    rts                                                               ; 1c4d: 60          .

; &1c4e referenced 1 time by &1c47
.sub_c1c4e
    ldx #0                                                            ; 1c4e: a2 00       ..
; &1c50 referenced 1 time by &1c57
.loop_c1c50
    lda ld000,x                                                       ; 1c50: bd 00 d0    ..P
    sta l4000,x                                                       ; 1c53: 9d 00 40    ..@
    inx                                                               ; 1c56: e8          .
    bne loop_c1c50                                                    ; 1c57: d0 f7       P.
    rts                                                               ; 1c59: 60          .

.pydis_end

    assert &1c0b == basic_end

save pydis_start - 2, pydis_end

; Label references by decreasing frequency:
;     mmu_configuration:          5
;     ld020:                      4
;     vic_border_colour:          4
;     basic_error_vector:         1
;     l00fb:                      1
;     l00fc:                      1
;     l1000:                      1
;     l4000:                      1
;     ld000:                      1
;     le000:                      1
;     loop_c1c50:                 1
;     mmu_configuration_io:       1
;     mmu_load_configuration_a:   1
;     sub_c1c4e:                  1
;     vic_background_colour_0:    1

; Automatically generated labels:
;     l00fb
;     l00fc
;     l4000
;     loop_c1c50
;     sub_c1c4e

; Stats:
;
;     Total size (Code + Data) = 89 bytes
;     Code                     = 77 bytes (87%)
;     Data                     = 12 bytes (13%)
;
;     Number of instructions   = 31
;     Number of data bytes     = 2 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1

