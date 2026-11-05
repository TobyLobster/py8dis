; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations

; Zero page ($0000-$00ff)
l0070   = $0070
l0071   = $0071

; I/O ($b000-$bfff)
ppi_port_a  = $b000
ppi_port_b  = $b001
ppi_port_c  = $b002
ppi_control = $b003

    .org $2900

pydis_start:
start:
    lda #$8a                                                          ; 2900: a9 8a       ..
    sta ppi_control                                                   ; 2902: 8d 03 b0    ... ; Set the 8255's modes: port A output, port B input, port C bits 4-7 input, bits 0-3 output
    lda #$f0                                                          ; 2905: a9 f0       ..
    sta ppi_port_a                                                    ; 2907: 8d 00 b0    ... ; Select graphics mode 4 (256x192, 2 colours)
    lda #$10                                                          ; 290a: a9 10       ..
    sta ppi_port_a                                                    ; 290c: 8d 00 b0    ... ; Select 64x64 graphics, 4 colours
    lda #0                                                            ; 290f: a9 00       ..
    sta ppi_port_a                                                    ; 2911: 8d 00 b0    ... ; Select text mode
    ldx #5                                                            ; 2914: a2 05       ..
    stx ppi_port_a                                                    ; 2916: 8e 00 b0    ... ; Select text mode, keyboard row 5
    lda ppi_port_a                                                    ; 2919: ad 00 b0    ...
    and #$f0                                                          ; 291c: 29 f0       ).
    ora #3                                                            ; 291e: 09 03       ..
    sta ppi_port_a                                                    ; 2920: 8d 00 b0    ... ; Select keyboard row 3
    inc ppi_port_a                                                    ; 2923: ee 00 b0    ... ; Select the next keyboard row
    lda ppi_port_c                                                    ; 2926: ad 02 b0    ...
    eor #4                                                            ; 2929: 49 04       I.
    sta ppi_port_c                                                    ; 292b: 8d 02 b0    ... ; Toggle the speaker
    lda ppi_port_c                                                    ; 292e: ad 02 b0    ...
    ora #8                                                            ; 2931: 09 08       ..
    sta ppi_port_c                                                    ; 2933: 8d 02 b0    ... ; Select colour set 1
    lda ppi_port_c                                                    ; 2936: ad 02 b0    ...
    and #$f7                                                          ; 2939: 29 f7       ).
    sta ppi_port_c                                                    ; 293b: 8d 02 b0    ... ; Select colour set 0
    lda #5                                                            ; 293e: a9 05       ..
    sta ppi_control                                                   ; 2940: 8d 03 b0    ... ; Set port C bit 2 (speaker high)
    lda #4                                                            ; 2943: a9 04       ..
    sta ppi_control                                                   ; 2945: 8d 03 b0    ... ; Clear port C bit 2 (speaker low)
; $2948 referenced 1 time by $294b
loop_c2948:
    bit ppi_port_c                                                    ; 2948: 2c 02 b0    ,.. ; Test the field sync
    bpl loop_c2948                                                    ; 294b: 10 fb       ..
    bit ppi_port_b                                                    ; 294d: 2c 01 b0    ,.. ; Test the SHIFT key (N) and the CTRL key (V)
    bit ppi_port_b                                                    ; 2950: 2c 01 b0    ,.. ; Test the CTRL key
    bvc c295c                                                         ; 2953: 50 07       P.
    lda #$10                                                          ; 2955: a9 10       ..
    bit ppi_port_c                                                    ; 2957: 2c 02 b0    ,.. ; Test the 2.4 kHz tape tone input
    beq c295c                                                         ; 295a: f0 00       ..
; $295c referenced 2 times by $2953, $295a
c295c:
    lda ppi_port_b                                                    ; 295c: ad 01 b0    ...
    and #$40 ; '@'                                                    ; 295f: 29 40       )@ ; Test the CTRL key
    sta l0070                                                         ; 2961: 85 70       .p
    lda ppi_port_c                                                    ; 2963: ad 02 b0    ...
    and #$40 ; '@'                                                    ; 2966: 29 40       )@ ; Test the REPT key
    sta l0071                                                         ; 2968: 85 71       .q
    rts                                                               ; 296a: 60          `

pydis_end:


; Label references by decreasing frequency:
;     ppi_port_c:    9
;     ppi_port_a:    7
;     ppi_control:   3
;     ppi_port_b:    3
;     c295c:         2
;     l0070:         1
;     l0071:         1
;     loop_c2948:    1

; Automatically generated labels:
;     c295c
;     l0070
;     l0071
;     loop_c2948

; Stats:
;
;     Total size (Code + Data) = 107 bytes
;     Code                     = 107 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 43
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

