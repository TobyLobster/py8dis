; Memory locations

; Zero page ($0000-$00ff)
jiffy_clock = $a0
l00fa       = $fa
l00fb       = $fb
l00fc       = $fc
l00fd       = $fd

; OS workspace ($0a00-$0aff)
vdc_screen_base = $0a2e

; Screen editor ROM ($c000-$cfff)
lc000   = $c000
vdcout  = $cdcc
vdcin   = $cdda

; SID ($d400-$d4ff)
sid_voice1_frequency_low    = $d400
sid_voice1_frequency_high   = $d401
sid_voice1_pulse_width_low  = $d402
sid_voice1_pulse_width_high = $d403
sid_voice1_control          = $d404
sid_voice1_attack_decay     = $d405
sid_voice1_sustain_release  = $d406
sid_voice3_frequency_low    = $d40e
sid_voice3_frequency_high   = $d40f
sid_voice3_control          = $d412
sid_volume_filter_mode      = $d418
sid_voice3_oscillator       = $d41b

; CIA 1 ($dc00-$dcff)
cia1_tod_tenths = $dc08
cia1_tod_seconds = $dc09

; MMU ($ff00-$ff04)
mmu_configuration   = $ff00

; Kernal entry points ($ff47-$fff9)
getin   = $ffe4

; The PRG file's header: the address to load it at
    * = $1bff
    !word $1c01

    * = $1c01

; 10 SYS8240
pydis_start
basic_line_10
    !word basic_end                                                   ; 1c01: 0b 1c       ..
    !word 10                                                          ; 1c03: 0a 00       ..
    !byte $9e                                                         ; 1c05: 9e          .
    !pet "8240"                                                       ; 1c06: 38 32 34... 824
    !byte 0                                                           ; 1c0a: 00          .
basic_end
    !word 0                                                           ; 1c0b: 00 00       ..
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c0d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c21: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c35: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c49: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c5d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c71: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c85: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1c99: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1cad: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1cc1: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1cd5: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1ce9: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1cfd: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d11: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d25: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d39: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d4d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d61: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d75: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d89: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1d9d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1db1: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1dc5: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1dd9: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1ded: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e01: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e15: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e29: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e3d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e51: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e65: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e79: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1e8d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1ea1: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1eb5: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1ec9: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1edd: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1ef1: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f05: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f19: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f2d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f41: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f55: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f69: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f7d: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1f91: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1fa5: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1fb9: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1fcd: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 1fe1: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                             ; 1ff5: 00 00 00... ...
; $2000 referenced 24 times by $2197, $21d2, $220d, $2248, $2283, $22be, $22f9, $2334, $236f, $23aa, $23e5, $2420, $245b, $2496, $24d1, $250c, $2661, $2772, $27a9, $27e1, $27fc, $2831, $2850, $2855
src_low
src_high = src_low+1
dst_low = src_low+2
dst_high = src_low+3
src_low_crd1 = src_low+4
src_high_crd1 = src_low+5
dst_low_crd1 = src_low+6
dst_high_crd1 = src_low+7
src_low_crd2 = src_low+8
src_high_crd2 = src_low+9
dst_low_crd2 = src_low+10
dst_high_crd2 = src_low+11
match = src_low+12
match_cnt = src_low+13
value_1 = src_low+14
value_2 = src_low+15
score = src_low+16
param = src_low+17
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0        ; 2000: 00 00 00... ...
; $2001 referenced 24 times by $219d, $21d8, $2213, $224e, $2289, $22c4, $22ff, $233a, $2375, $23b0, $23eb, $2426, $2461, $249c, $24d7, $2512, $2666, $2778, $27af, $27e7, $2802, $2829, $2858, $285d
; $2002 referenced 76 times by $2172, $2185, $21ad, $21c0, $21e8, $21fb, $2223, $2236, $225e, $2271, $2299, $22ac, $22d4, $22e7, $230f, $2322, $234a, $235d, $2385, $2398, $23c0, $23d3, $23fb, $240e, $2436, $2449, $2471, $2484, $24ac, $24bf, $24e7, $24fa, $2657, $26f9, $270c, $274a, $2756, $2781, $278d, $27d5, $27f0, $2821, $283f, $2844, $2869, $287c, $288f, $28a2, $28b5, $28c8, $28db, $28ee, $2901, $2914, $2927, $293a, $294d, $2960, $2973, $2986, $2999, $29ac, $29bf, $29d2, $29e5, $29f8, $2a0b, $2a1e, $2a31, $2a44, $2a57, $2a6a, $2a7d, $2a90, $2aa3, $2ab6
; $2003 referenced 76 times by $2178, $217d, $21b3, $21b8, $21ee, $21f3, $2229, $222e, $2264, $2269, $229f, $22a4, $22da, $22df, $2315, $231a, $2350, $2355, $238b, $2390, $23c6, $23cb, $2401, $2406, $243c, $2441, $2477, $247c, $24b2, $24b7, $24ed, $24f2, $265c, $26ff, $2712, $2750, $2760, $2787, $2797, $27db, $27f6, $2819, $2847, $284c, $286f, $2874, $2895, $289a, $28bb, $28c0, $28e1, $28e6, $2907, $290c, $292d, $2932, $2953, $2958, $2979, $297e, $299f, $29a4, $29c5, $29ca, $29eb, $29f0, $2a11, $2a16, $2a37, $2a3c, $2a5d, $2a62, $2a83, $2a88, $2aa9, $2aae
; $2006 referenced 3 times by $26fc, $2747, $27d2
; $2007 referenced 3 times by $2702, $274d, $27d8
; $200a referenced 3 times by $270f, $277e, $27ed
; $200b referenced 3 times by $2715, $2784, $27f3
; $200c referenced 19 times by $21a3, $21de, $2219, $2254, $228f, $22ca, $2305, $2340, $237b, $23b6, $23f1, $242c, $2467, $24a2, $24dd, $2518, $26f5, $2705, $2718
; $200d referenced 4 times by $26b9, $26bc, $26c3, $26f2
; $200e referenced 2 times by $26ca, $2708
; $200f referenced 3 times by $26cd, $26d3, $271b
; $2010 referenced 7 times by $2108, $26da, $26e0, $26ea, $2724, $272a, $2b05
; $2011 referenced 6 times by $2b08, $2b0d, $2b15, $2b7d, $2b85, $2bef
; $2012 referenced 2 times by $2130, $2139
jump_addr
l2013 = jump_addr+1
    !word 0                                                           ; 2012: 00 00       ..
; $2013 referenced 1 time by $2136
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2014: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0                                      ; 2028: 00 00 00... ...

sys_entry
start
    jsr lc000                                                         ; 2030: 20 00 c0     ..
    lda #6                                                            ; 2033: a9 06       ..
    sta mmu_configuration                                             ; 2035: 8d 00 ff    ...
    lda #$8f                                                          ; 2038: a9 8f       ..
    sta sid_volume_filter_mode                                        ; 203a: 8d 18 d4    ..T
    lda #8                                                            ; 203d: a9 08       ..
    sta sid_voice3_control                                            ; 203f: 8d 12 d4    ..T
    lda #$6c                                                          ; 2042: a9 6c       ..
    sta sid_voice3_frequency_low                                      ; 2044: 8d 0e d4    ..T
    lda #$61                                                          ; 2047: a9 61       ..
    sta sid_voice3_frequency_high                                     ; 2049: 8d 0f d4    ..T
    lda #$80                                                          ; 204c: a9 80       ..
    sta sid_voice3_control                                            ; 204e: 8d 12 d4    ..T
    lda #0                                                            ; 2051: a9 00       ..
    sta l00fa                                                         ; 2053: 85 fa       ..
    sta l00fb                                                         ; 2055: 85 fb       ..
    lda #0                                                            ; 2057: a9 00       ..
    sta l00fc                                                         ; 2059: 85 fc       ..
    lda #$30 ; '0'                                                    ; 205b: a9 30       .0
    sta l00fd                                                         ; 205d: 85 fd       ..
    ldy #0                                                            ; 205f: a0 00       ..
    ldx #$12                                                          ; 2061: a2 12       ..
    lda #0                                                            ; 2063: a9 00       ..
    jsr vdcout                                                        ; 2065: 20 cc cd     LM
    ldx #$13                                                          ; 2068: a2 13       ..
    lda #0                                                            ; 206a: a9 00       ..
    jsr vdcout                                                        ; 206c: 20 cc cd     LM
; $206f referenced 2 times by $207a, $2084
loop_ch
    ldx #$1f                                                          ; 206f: a2 1f       ..
    ldy l00fa                                                         ; 2071: a4 fa       ..
    lda (l00fc),y                                                     ; 2073: b1 fc       ..
    jsr vdcout                                                        ; 2075: 20 cc cd     LM
    inc l00fa                                                         ; 2078: e6 fa       ..
    bne loop_ch                                                       ; 207a: d0 f3       P.
    inc l00fd                                                         ; 207c: e6 fd       ..
    inc l00fb                                                         ; 207e: e6 fb       ..
    lda l00fb                                                         ; 2080: a5 fb       ..
    cmp #8                                                            ; 2082: c9 08       I.
    bne loop_ch                                                       ; 2084: d0 e9       P.
    lda #0                                                            ; 2086: a9 00       ..
    sta l00fa                                                         ; 2088: 85 fa       ..
    sta l00fb                                                         ; 208a: 85 fb       ..
    lda #0                                                            ; 208c: a9 00       ..
    sta l00fc                                                         ; 208e: 85 fc       ..
    lda #$38 ; '8'                                                    ; 2090: a9 38       .8
    sta l00fd                                                         ; 2092: 85 fd       ..
    ldy #0                                                            ; 2094: a0 00       ..
    ldx #$12                                                          ; 2096: a2 12       ..
    lda #$10                                                          ; 2098: a9 10       ..
    jsr vdcout                                                        ; 209a: 20 cc cd     LM
    ldx #$13                                                          ; 209d: a2 13       ..
    lda #0                                                            ; 209f: a9 00       ..
    jsr vdcout                                                        ; 20a1: 20 cc cd     LM
; $20a4 referenced 2 times by $20af, $20b9
loop_ch2
    ldx #$1f                                                          ; 20a4: a2 1f       ..
    ldy l00fa                                                         ; 20a6: a4 fa       ..
    lda (l00fc),y                                                     ; 20a8: b1 fc       ..
    jsr vdcout                                                        ; 20aa: 20 cc cd     LM
    inc l00fa                                                         ; 20ad: e6 fa       ..
    bne loop_ch2                                                      ; 20af: d0 f3       P.
    inc l00fd                                                         ; 20b1: e6 fd       ..
    inc l00fb                                                         ; 20b3: e6 fb       ..
    lda l00fb                                                         ; 20b5: a5 fb       ..
    cmp #5                                                            ; 20b7: c9 05       I.
    bne loop_ch2                                                      ; 20b9: d0 e9       P.
    lda #0                                                            ; 20bb: a9 00       ..
    sta l00fa                                                         ; 20bd: 85 fa       ..
    sta l00fb                                                         ; 20bf: 85 fb       ..
    lda #0                                                            ; 20c1: a9 00       ..
    sta l00fc                                                         ; 20c3: 85 fc       ..
    lda #$40 ; '@'                                                    ; 20c5: a9 40       .@
    sta l00fd                                                         ; 20c7: 85 fd       ..
    ldy #0                                                            ; 20c9: a0 00       ..
    ldx #$12                                                          ; 20cb: a2 12       ..
    lda #$18                                                          ; 20cd: a9 18       ..
    jsr vdcout                                                        ; 20cf: 20 cc cd     LM
    ldx #$13                                                          ; 20d2: a2 13       ..
    lda #0                                                            ; 20d4: a9 00       ..
    jsr vdcout                                                        ; 20d6: 20 cc cd     LM
; $20d9 referenced 2 times by $20e4, $20ee
loop_ch3
    ldx #$1f                                                          ; 20d9: a2 1f       ..
    ldy l00fa                                                         ; 20db: a4 fa       ..
    lda (l00fc),y                                                     ; 20dd: b1 fc       ..
    jsr vdcout                                                        ; 20df: 20 cc cd     LM
    inc l00fa                                                         ; 20e2: e6 fa       ..
    bne loop_ch3                                                      ; 20e4: d0 f3       P.
    inc l00fd                                                         ; 20e6: e6 fd       ..
    inc l00fb                                                         ; 20e8: e6 fb       ..
    lda l00fb                                                         ; 20ea: a5 fb       ..
    cmp #8                                                            ; 20ec: c9 08       I.
    bne loop_ch3                                                      ; 20ee: d0 e9       P.
    jsr fill_unique_array                                             ; 20f0: 20 85 25     .%
    jsr copy                                                          ; 20f3: 20 cb 25     K%
; $20f6 referenced 1 time by $2101
main_loop
    jsr decout                                                        ; 20f6: 20 05 2b     .+
    jsr check_no_cards                                                ; 20f9: 20 66 28     .(
    jsr handle_input                                                  ; 20fc: 20 14 21     .!
    cmp #$58 ; 'x'                                                    ; 20ff: c9 58       Ix
    bne main_loop                                                     ; 2101: d0 f3       P.
    jsr exit                                                          ; 2103: 20 06 21     .!
; $2106 referenced 1 time by $2103
exit
    lda #0                                                            ; 2106: a9 00       ..
    sta score                                                         ; 2108: 8d 10 20    ..
    jsr lc000                                                         ; 210b: 20 00 c0     ..
    lda #0                                                            ; 210e: a9 00       ..
    sta mmu_configuration                                             ; 2110: 8d 00 ff    ...
    rts                                                               ; 2113: 60          .

; $2114 referenced 1 time by $20fc
handle_input
    jsr getin                                                         ; 2114: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq no_key                                                        ; 2117: f0 24       .$
    cmp #$58 ; 'x'                                                    ; 2119: c9 58       Ix ; A=character read
    beq quit_game                                                     ; 211b: f0 1f       ..
    ldx #0                                                            ; 211d: a2 00       ..
; $211f referenced 1 time by $2127
search_loop
    cmp key_table,x                                                   ; 211f: dd 3f 21    .?!
    beq found_key                                                     ; 2122: f0 06       ..
    inx                                                               ; 2124: e8          .
    cpx #$10                                                          ; 2125: e0 10       ..
    bne search_loop                                                   ; 2127: d0 f6       P.
    rts                                                               ; 2129: 60          .

; $212a referenced 1 time by $2122
found_key
    txa                                                               ; 212a: 8a          .
    asl                                                               ; 212b: 0a          .
    tax                                                               ; 212c: aa          .
    lda handler_table,x                                               ; 212d: bd 4f 21    .o!
    sta jump_addr                                                     ; 2130: 8d 12 20    ..
    lda l2150,x                                                       ; 2133: bd 50 21    .p!
    sta l2013                                                         ; 2136: 8d 13 20    ..
    jmp (jump_addr)                                                   ; 2139: 6c 12 20    ..

; $213c referenced 1 time by $211b
quit_game
    rts                                                               ; 213c: 60          .

; $213d referenced 1 time by $2117
no_key
    rts                                                               ; 213d: 60          .

invalid_key
    !byte $60                                                         ; 213e: 60          .
; $213f referenced 1 time by $211f
key_table
    !pet "12345678qwertyui"                                           ; 213f: 31 32 33... 123
; $214f referenced 1 time by $212d
handler_table
l2150 = handler_table+1
    !word show_1, show_2, show_3, show_4, show_5, show_6, show_7      ; 214f: 6f 21 aa... .!.
    !word show_8, show_Q, show_W, show_E, show_R, show_T, show_Y      ; 215d: 0c 23 47... .#g
    !word show_U, show_I                                              ; 216b: a9 24 e4... .$.
; $2150 referenced 1 time by $2133

show_1
    lda l2521                                                         ; 216f: ad 21 25    .!%
    sta dst_low                                                       ; 2172: 8d 02 20    ..
    lda l2522                                                         ; 2175: ad 22 25    ."%
    sta dst_high                                                      ; 2178: 8d 03 20    ..
    ldx #$12                                                          ; 217b: a2 12       ..
    lda dst_high                                                      ; 217d: ad 03 20    ..
    jsr vdcout                                                        ; 2180: 20 cc cd     LM
    ldx #$13                                                          ; 2183: a2 13       ..
    lda dst_low                                                       ; 2185: ad 02 20    ..
    jsr vdcout                                                        ; 2188: 20 cc cd     LM
    ldx #$1f                                                          ; 218b: a2 1f       ..
    jsr vdcin                                                         ; 218d: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2190: c9 20       I
    beq return_1                                                      ; 2192: f0 15       ..
    lda card_face_array                                               ; 2194: ad 15 26    ..&
    sta src_low                                                       ; 2197: 8d 00 20    ..
    lda l2616                                                         ; 219a: ad 16 26    ..&
    sta src_high                                                      ; 219d: 8d 01 20    ..
    lda l2617                                                         ; 21a0: ad 17 26    ..&
    sta match                                                         ; 21a3: 8d 0c 20    ..
    jsr display_card                                                  ; 21a6: 20 55 26     u&
; $21a9 referenced 1 time by $2192
return_1
    rts                                                               ; 21a9: 60          .

show_2
    lda l2523                                                         ; 21aa: ad 23 25    .#%
    sta dst_low                                                       ; 21ad: 8d 02 20    ..
    lda l2524                                                         ; 21b0: ad 24 25    .$%
    sta dst_high                                                      ; 21b3: 8d 03 20    ..
    ldx #$12                                                          ; 21b6: a2 12       ..
    lda dst_high                                                      ; 21b8: ad 03 20    ..
    jsr vdcout                                                        ; 21bb: 20 cc cd     LM
    ldx #$13                                                          ; 21be: a2 13       ..
    lda dst_low                                                       ; 21c0: ad 02 20    ..
    jsr vdcout                                                        ; 21c3: 20 cc cd     LM
    ldx #$1f                                                          ; 21c6: a2 1f       ..
    jsr vdcin                                                         ; 21c8: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 21cb: c9 20       I
    beq return_2                                                      ; 21cd: f0 15       ..
    lda l2619                                                         ; 21cf: ad 19 26    ..&
    sta src_low                                                       ; 21d2: 8d 00 20    ..
    lda l261a                                                         ; 21d5: ad 1a 26    ..&
    sta src_high                                                      ; 21d8: 8d 01 20    ..
    lda l261b                                                         ; 21db: ad 1b 26    ..&
    sta match                                                         ; 21de: 8d 0c 20    ..
    jsr display_card                                                  ; 21e1: 20 55 26     u&
; $21e4 referenced 1 time by $21cd
return_2
    rts                                                               ; 21e4: 60          .

show_3
    lda l2525                                                         ; 21e5: ad 25 25    .%%
    sta dst_low                                                       ; 21e8: 8d 02 20    ..
    lda l2526                                                         ; 21eb: ad 26 25    .&%
    sta dst_high                                                      ; 21ee: 8d 03 20    ..
    ldx #$12                                                          ; 21f1: a2 12       ..
    lda dst_high                                                      ; 21f3: ad 03 20    ..
    jsr vdcout                                                        ; 21f6: 20 cc cd     LM
    ldx #$13                                                          ; 21f9: a2 13       ..
    lda dst_low                                                       ; 21fb: ad 02 20    ..
    jsr vdcout                                                        ; 21fe: 20 cc cd     LM
    ldx #$1f                                                          ; 2201: a2 1f       ..
    jsr vdcin                                                         ; 2203: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2206: c9 20       I
    beq return_3                                                      ; 2208: f0 15       ..
    lda l261d                                                         ; 220a: ad 1d 26    ..&
    sta src_low                                                       ; 220d: 8d 00 20    ..
    lda l261e                                                         ; 2210: ad 1e 26    ..&
    sta src_high                                                      ; 2213: 8d 01 20    ..
    lda l261f                                                         ; 2216: ad 1f 26    ..&
    sta match                                                         ; 2219: 8d 0c 20    ..
    jsr display_card                                                  ; 221c: 20 55 26     u&
; $221f referenced 1 time by $2208
return_3
    rts                                                               ; 221f: 60          .

show_4
    lda l2527                                                         ; 2220: ad 27 25    .'%
    sta dst_low                                                       ; 2223: 8d 02 20    ..
    lda l2528                                                         ; 2226: ad 28 25    .(%
    sta dst_high                                                      ; 2229: 8d 03 20    ..
    ldx #$12                                                          ; 222c: a2 12       ..
    lda dst_high                                                      ; 222e: ad 03 20    ..
    jsr vdcout                                                        ; 2231: 20 cc cd     LM
    ldx #$13                                                          ; 2234: a2 13       ..
    lda dst_low                                                       ; 2236: ad 02 20    ..
    jsr vdcout                                                        ; 2239: 20 cc cd     LM
    ldx #$1f                                                          ; 223c: a2 1f       ..
    jsr vdcin                                                         ; 223e: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2241: c9 20       I
    beq return_4                                                      ; 2243: f0 15       ..
    lda l2621                                                         ; 2245: ad 21 26    .!&
    sta src_low                                                       ; 2248: 8d 00 20    ..
    lda l2622                                                         ; 224b: ad 22 26    ."&
    sta src_high                                                      ; 224e: 8d 01 20    ..
    lda l2623                                                         ; 2251: ad 23 26    .#&
    sta match                                                         ; 2254: 8d 0c 20    ..
    jsr display_card                                                  ; 2257: 20 55 26     u&
; $225a referenced 1 time by $2243
return_4
    rts                                                               ; 225a: 60          .

show_5
    lda l2529                                                         ; 225b: ad 29 25    .)%
    sta dst_low                                                       ; 225e: 8d 02 20    ..
    lda l252a                                                         ; 2261: ad 2a 25    .*%
    sta dst_high                                                      ; 2264: 8d 03 20    ..
    ldx #$12                                                          ; 2267: a2 12       ..
    lda dst_high                                                      ; 2269: ad 03 20    ..
    jsr vdcout                                                        ; 226c: 20 cc cd     LM
    ldx #$13                                                          ; 226f: a2 13       ..
    lda dst_low                                                       ; 2271: ad 02 20    ..
    jsr vdcout                                                        ; 2274: 20 cc cd     LM
    ldx #$1f                                                          ; 2277: a2 1f       ..
    jsr vdcin                                                         ; 2279: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 227c: c9 20       I
    beq return_5                                                      ; 227e: f0 15       ..
    lda l2625                                                         ; 2280: ad 25 26    .%&
    sta src_low                                                       ; 2283: 8d 00 20    ..
    lda l2626                                                         ; 2286: ad 26 26    .&&
    sta src_high                                                      ; 2289: 8d 01 20    ..
    lda l2627                                                         ; 228c: ad 27 26    .'&
    sta match                                                         ; 228f: 8d 0c 20    ..
    jsr display_card                                                  ; 2292: 20 55 26     u&
; $2295 referenced 1 time by $227e
return_5
    rts                                                               ; 2295: 60          .

show_6
    lda l252b                                                         ; 2296: ad 2b 25    .+%
    sta dst_low                                                       ; 2299: 8d 02 20    ..
    lda l252c                                                         ; 229c: ad 2c 25    .,%
    sta dst_high                                                      ; 229f: 8d 03 20    ..
    ldx #$12                                                          ; 22a2: a2 12       ..
    lda dst_high                                                      ; 22a4: ad 03 20    ..
    jsr vdcout                                                        ; 22a7: 20 cc cd     LM
    ldx #$13                                                          ; 22aa: a2 13       ..
    lda dst_low                                                       ; 22ac: ad 02 20    ..
    jsr vdcout                                                        ; 22af: 20 cc cd     LM
    ldx #$1f                                                          ; 22b2: a2 1f       ..
    jsr vdcin                                                         ; 22b4: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 22b7: c9 20       I
    beq return_6                                                      ; 22b9: f0 15       ..
    lda l2629                                                         ; 22bb: ad 29 26    .)&
    sta src_low                                                       ; 22be: 8d 00 20    ..
    lda l262a                                                         ; 22c1: ad 2a 26    .*&
    sta src_high                                                      ; 22c4: 8d 01 20    ..
    lda l262b                                                         ; 22c7: ad 2b 26    .+&
    sta match                                                         ; 22ca: 8d 0c 20    ..
    jsr display_card                                                  ; 22cd: 20 55 26     u&
; $22d0 referenced 1 time by $22b9
return_6
    rts                                                               ; 22d0: 60          .

show_7
    lda l252d                                                         ; 22d1: ad 2d 25    .-%
    sta dst_low                                                       ; 22d4: 8d 02 20    ..
    lda l252e                                                         ; 22d7: ad 2e 25    ..%
    sta dst_high                                                      ; 22da: 8d 03 20    ..
    ldx #$12                                                          ; 22dd: a2 12       ..
    lda dst_high                                                      ; 22df: ad 03 20    ..
    jsr vdcout                                                        ; 22e2: 20 cc cd     LM
    ldx #$13                                                          ; 22e5: a2 13       ..
    lda dst_low                                                       ; 22e7: ad 02 20    ..
    jsr vdcout                                                        ; 22ea: 20 cc cd     LM
    ldx #$1f                                                          ; 22ed: a2 1f       ..
    jsr vdcin                                                         ; 22ef: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 22f2: c9 20       I
    beq return_7                                                      ; 22f4: f0 15       ..
    lda l262d                                                         ; 22f6: ad 2d 26    .-&
    sta src_low                                                       ; 22f9: 8d 00 20    ..
    lda l262e                                                         ; 22fc: ad 2e 26    ..&
    sta src_high                                                      ; 22ff: 8d 01 20    ..
    lda l262f                                                         ; 2302: ad 2f 26    ./&
    sta match                                                         ; 2305: 8d 0c 20    ..
    jsr display_card                                                  ; 2308: 20 55 26     u&
; $230b referenced 1 time by $22f4
return_7
    rts                                                               ; 230b: 60          .

show_8
    lda l252f                                                         ; 230c: ad 2f 25    ./%
    sta dst_low                                                       ; 230f: 8d 02 20    ..
    lda l2530                                                         ; 2312: ad 30 25    .0%
    sta dst_high                                                      ; 2315: 8d 03 20    ..
    ldx #$12                                                          ; 2318: a2 12       ..
    lda dst_high                                                      ; 231a: ad 03 20    ..
    jsr vdcout                                                        ; 231d: 20 cc cd     LM
    ldx #$13                                                          ; 2320: a2 13       ..
    lda dst_low                                                       ; 2322: ad 02 20    ..
    jsr vdcout                                                        ; 2325: 20 cc cd     LM
    ldx #$1f                                                          ; 2328: a2 1f       ..
    jsr vdcin                                                         ; 232a: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 232d: c9 20       I
    beq return_8                                                      ; 232f: f0 15       ..
    lda l2631                                                         ; 2331: ad 31 26    .1&
    sta src_low                                                       ; 2334: 8d 00 20    ..
    lda l2632                                                         ; 2337: ad 32 26    .2&
    sta src_high                                                      ; 233a: 8d 01 20    ..
    lda l2633                                                         ; 233d: ad 33 26    .3&
    sta match                                                         ; 2340: 8d 0c 20    ..
    jsr display_card                                                  ; 2343: 20 55 26     u&
; $2346 referenced 1 time by $232f
return_8
    rts                                                               ; 2346: 60          .

show_Q
    lda l2531                                                         ; 2347: ad 31 25    .1%
    sta dst_low                                                       ; 234a: 8d 02 20    ..
    lda l2532                                                         ; 234d: ad 32 25    .2%
    sta dst_high                                                      ; 2350: 8d 03 20    ..
    ldx #$12                                                          ; 2353: a2 12       ..
    lda dst_high                                                      ; 2355: ad 03 20    ..
    jsr vdcout                                                        ; 2358: 20 cc cd     LM
    ldx #$13                                                          ; 235b: a2 13       ..
    lda dst_low                                                       ; 235d: ad 02 20    ..
    jsr vdcout                                                        ; 2360: 20 cc cd     LM
    ldx #$1f                                                          ; 2363: a2 1f       ..
    jsr vdcin                                                         ; 2365: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2368: c9 20       I
    beq return_9                                                      ; 236a: f0 15       ..
    lda l2635                                                         ; 236c: ad 35 26    .5&
    sta src_low                                                       ; 236f: 8d 00 20    ..
    lda l2636                                                         ; 2372: ad 36 26    .6&
    sta src_high                                                      ; 2375: 8d 01 20    ..
    lda l2637                                                         ; 2378: ad 37 26    .7&
    sta match                                                         ; 237b: 8d 0c 20    ..
    jsr display_card                                                  ; 237e: 20 55 26     u&
; $2381 referenced 1 time by $236a
return_9
    rts                                                               ; 2381: 60          .

show_W
    lda l2533                                                         ; 2382: ad 33 25    .3%
    sta dst_low                                                       ; 2385: 8d 02 20    ..
    lda l2534                                                         ; 2388: ad 34 25    .4%
    sta dst_high                                                      ; 238b: 8d 03 20    ..
    ldx #$12                                                          ; 238e: a2 12       ..
    lda dst_high                                                      ; 2390: ad 03 20    ..
    jsr vdcout                                                        ; 2393: 20 cc cd     LM
    ldx #$13                                                          ; 2396: a2 13       ..
    lda dst_low                                                       ; 2398: ad 02 20    ..
    jsr vdcout                                                        ; 239b: 20 cc cd     LM
    ldx #$1f                                                          ; 239e: a2 1f       ..
    jsr vdcin                                                         ; 23a0: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 23a3: c9 20       I
    beq return_10                                                     ; 23a5: f0 15       ..
    lda l2639                                                         ; 23a7: ad 39 26    .9&
    sta src_low                                                       ; 23aa: 8d 00 20    ..
    lda l263a                                                         ; 23ad: ad 3a 26    .:&
    sta src_high                                                      ; 23b0: 8d 01 20    ..
    lda l263b                                                         ; 23b3: ad 3b 26    .;&
    sta match                                                         ; 23b6: 8d 0c 20    ..
    jsr display_card                                                  ; 23b9: 20 55 26     u&
; $23bc referenced 1 time by $23a5
return_10
    rts                                                               ; 23bc: 60          .

show_E
    lda l2535                                                         ; 23bd: ad 35 25    .5%
    sta dst_low                                                       ; 23c0: 8d 02 20    ..
    lda l2536                                                         ; 23c3: ad 36 25    .6%
    sta dst_high                                                      ; 23c6: 8d 03 20    ..
    ldx #$12                                                          ; 23c9: a2 12       ..
    lda dst_high                                                      ; 23cb: ad 03 20    ..
    jsr vdcout                                                        ; 23ce: 20 cc cd     LM
    ldx #$13                                                          ; 23d1: a2 13       ..
    lda dst_low                                                       ; 23d3: ad 02 20    ..
    jsr vdcout                                                        ; 23d6: 20 cc cd     LM
    ldx #$1f                                                          ; 23d9: a2 1f       ..
    jsr vdcin                                                         ; 23db: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 23de: c9 20       I
    beq return_11                                                     ; 23e0: f0 15       ..
    lda l263d                                                         ; 23e2: ad 3d 26    .=&
    sta src_low                                                       ; 23e5: 8d 00 20    ..
    lda l263e                                                         ; 23e8: ad 3e 26    .>&
    sta src_high                                                      ; 23eb: 8d 01 20    ..
    lda l263f                                                         ; 23ee: ad 3f 26    .?&
    sta match                                                         ; 23f1: 8d 0c 20    ..
    jsr display_card                                                  ; 23f4: 20 55 26     u&
; $23f7 referenced 1 time by $23e0
return_11
    rts                                                               ; 23f7: 60          .

show_R
    lda l2537                                                         ; 23f8: ad 37 25    .7%
    sta dst_low                                                       ; 23fb: 8d 02 20    ..
    lda l2538                                                         ; 23fe: ad 38 25    .8%
    sta dst_high                                                      ; 2401: 8d 03 20    ..
    ldx #$12                                                          ; 2404: a2 12       ..
    lda dst_high                                                      ; 2406: ad 03 20    ..
    jsr vdcout                                                        ; 2409: 20 cc cd     LM
    ldx #$13                                                          ; 240c: a2 13       ..
    lda dst_low                                                       ; 240e: ad 02 20    ..
    jsr vdcout                                                        ; 2411: 20 cc cd     LM
    ldx #$1f                                                          ; 2414: a2 1f       ..
    jsr vdcin                                                         ; 2416: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2419: c9 20       I
    beq return_12                                                     ; 241b: f0 15       ..
    lda l2641                                                         ; 241d: ad 41 26    .a&
    sta src_low                                                       ; 2420: 8d 00 20    ..
    lda l2642                                                         ; 2423: ad 42 26    .b&
    sta src_high                                                      ; 2426: 8d 01 20    ..
    lda l2643                                                         ; 2429: ad 43 26    .c&
    sta match                                                         ; 242c: 8d 0c 20    ..
    jsr display_card                                                  ; 242f: 20 55 26     u&
; $2432 referenced 1 time by $241b
return_12
    rts                                                               ; 2432: 60          .

show_T
    lda l2539                                                         ; 2433: ad 39 25    .9%
    sta dst_low                                                       ; 2436: 8d 02 20    ..
    lda l253a                                                         ; 2439: ad 3a 25    .:%
    sta dst_high                                                      ; 243c: 8d 03 20    ..
    ldx #$12                                                          ; 243f: a2 12       ..
    lda dst_high                                                      ; 2441: ad 03 20    ..
    jsr vdcout                                                        ; 2444: 20 cc cd     LM
    ldx #$13                                                          ; 2447: a2 13       ..
    lda dst_low                                                       ; 2449: ad 02 20    ..
    jsr vdcout                                                        ; 244c: 20 cc cd     LM
    ldx #$1f                                                          ; 244f: a2 1f       ..
    jsr vdcin                                                         ; 2451: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2454: c9 20       I
    beq return_13                                                     ; 2456: f0 15       ..
    lda l2645                                                         ; 2458: ad 45 26    .e&
    sta src_low                                                       ; 245b: 8d 00 20    ..
    lda l2646                                                         ; 245e: ad 46 26    .f&
    sta src_high                                                      ; 2461: 8d 01 20    ..
    lda l2647                                                         ; 2464: ad 47 26    .g&
    sta match                                                         ; 2467: 8d 0c 20    ..
    jsr display_card                                                  ; 246a: 20 55 26     u&
; $246d referenced 1 time by $2456
return_13
    rts                                                               ; 246d: 60          .

show_Y
    lda l253b                                                         ; 246e: ad 3b 25    .;%
    sta dst_low                                                       ; 2471: 8d 02 20    ..
    lda l253c                                                         ; 2474: ad 3c 25    .<%
    sta dst_high                                                      ; 2477: 8d 03 20    ..
    ldx #$12                                                          ; 247a: a2 12       ..
    lda dst_high                                                      ; 247c: ad 03 20    ..
    jsr vdcout                                                        ; 247f: 20 cc cd     LM
    ldx #$13                                                          ; 2482: a2 13       ..
    lda dst_low                                                       ; 2484: ad 02 20    ..
    jsr vdcout                                                        ; 2487: 20 cc cd     LM
    ldx #$1f                                                          ; 248a: a2 1f       ..
    jsr vdcin                                                         ; 248c: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 248f: c9 20       I
    beq return_14                                                     ; 2491: f0 15       ..
    lda l2649                                                         ; 2493: ad 49 26    .i&
    sta src_low                                                       ; 2496: 8d 00 20    ..
    lda l264a                                                         ; 2499: ad 4a 26    .j&
    sta src_high                                                      ; 249c: 8d 01 20    ..
    lda l264b                                                         ; 249f: ad 4b 26    .k&
    sta match                                                         ; 24a2: 8d 0c 20    ..
    jsr display_card                                                  ; 24a5: 20 55 26     u&
; $24a8 referenced 1 time by $2491
return_14
    rts                                                               ; 24a8: 60          .

show_U
    lda l253d                                                         ; 24a9: ad 3d 25    .=%
    sta dst_low                                                       ; 24ac: 8d 02 20    ..
    lda l253e                                                         ; 24af: ad 3e 25    .>%
    sta dst_high                                                      ; 24b2: 8d 03 20    ..
    ldx #$12                                                          ; 24b5: a2 12       ..
    lda dst_high                                                      ; 24b7: ad 03 20    ..
    jsr vdcout                                                        ; 24ba: 20 cc cd     LM
    ldx #$13                                                          ; 24bd: a2 13       ..
    lda dst_low                                                       ; 24bf: ad 02 20    ..
    jsr vdcout                                                        ; 24c2: 20 cc cd     LM
    ldx #$1f                                                          ; 24c5: a2 1f       ..
    jsr vdcin                                                         ; 24c7: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 24ca: c9 20       I
    beq return_15                                                     ; 24cc: f0 15       ..
    lda l264d                                                         ; 24ce: ad 4d 26    .m&
    sta src_low                                                       ; 24d1: 8d 00 20    ..
    lda l264e                                                         ; 24d4: ad 4e 26    .n&
    sta src_high                                                      ; 24d7: 8d 01 20    ..
    lda l264f                                                         ; 24da: ad 4f 26    .o&
    sta match                                                         ; 24dd: 8d 0c 20    ..
    jsr display_card                                                  ; 24e0: 20 55 26     u&
; $24e3 referenced 1 time by $24cc
return_15
    rts                                                               ; 24e3: 60          .

show_I
    lda l253f                                                         ; 24e4: ad 3f 25    .?%
    sta dst_low                                                       ; 24e7: 8d 02 20    ..
    lda l2540                                                         ; 24ea: ad 40 25    .@%
    sta dst_high                                                      ; 24ed: 8d 03 20    ..
    ldx #$12                                                          ; 24f0: a2 12       ..
    lda dst_high                                                      ; 24f2: ad 03 20    ..
    jsr vdcout                                                        ; 24f5: 20 cc cd     LM
    ldx #$13                                                          ; 24f8: a2 13       ..
    lda dst_low                                                       ; 24fa: ad 02 20    ..
    jsr vdcout                                                        ; 24fd: 20 cc cd     LM
    ldx #$1f                                                          ; 2500: a2 1f       ..
    jsr vdcin                                                         ; 2502: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2505: c9 20       I
    beq return_16                                                     ; 2507: f0 15       ..
    lda l2651                                                         ; 2509: ad 51 26    .q&
    sta src_low                                                       ; 250c: 8d 00 20    ..
    lda l2652                                                         ; 250f: ad 52 26    .r&
    sta src_high                                                      ; 2512: 8d 01 20    ..
    lda l2653                                                         ; 2515: ad 53 26    .s&
    sta match                                                         ; 2518: 8d 0c 20    ..
    jsr display_card                                                  ; 251b: 20 55 26     u&
; $251e referenced 1 time by $2507
return_16
    rts                                                               ; 251e: 60          .

; $251f referenced 1 time by $2866
card_pos_array
    !byte 0                                                           ; 251f: 00          .
; $2520 referenced 1 time by $286c
l2520
    !byte 0                                                           ; 2520: 00          .
; $2521 referenced 2 times by $216f, $288c
l2521
    !byte $51                                                         ; 2521: 51          q
; $2522 referenced 2 times by $2175, $2892
l2522
    !byte 0                                                           ; 2522: 00          .
; $2523 referenced 2 times by $21aa, $28b2
l2523
    !byte $5b                                                         ; 2523: 5b          [
; $2524 referenced 2 times by $21b0, $28b8
l2524
    !byte 0                                                           ; 2524: 00          .
; $2525 referenced 2 times by $21e5, $28d8
l2525
    !byte $65                                                         ; 2525: 65          .
; $2526 referenced 2 times by $21eb, $28de
l2526
    !byte 0                                                           ; 2526: 00          .
; $2527 referenced 2 times by $2220, $28fe
l2527
    !byte $6f                                                         ; 2527: 6f          .
; $2528 referenced 2 times by $2226, $2904
l2528
    !byte 0                                                           ; 2528: 00          .
; $2529 referenced 2 times by $225b, $2924
l2529
    !byte $79                                                         ; 2529: 79          .
; $252a referenced 2 times by $2261, $292a
l252a
    !byte 0                                                           ; 252a: 00          .
; $252b referenced 2 times by $2296, $294a
l252b
    !byte $83                                                         ; 252b: 83          .
; $252c referenced 2 times by $229c, $2950
l252c
    !byte 0                                                           ; 252c: 00          .
; $252d referenced 2 times by $22d1, $2970
l252d
    !byte $8d                                                         ; 252d: 8d          .
; $252e referenced 2 times by $22d7, $2976
l252e
    !byte 0                                                           ; 252e: 00          .
; $252f referenced 2 times by $230c, $2996
l252f
    !byte $97                                                         ; 252f: 97          .
; $2530 referenced 2 times by $2312, $299c
l2530
    !byte 0                                                           ; 2530: 00          .
; $2531 referenced 2 times by $2347, $29bc
l2531
    !byte $11                                                         ; 2531: 11          .
; $2532 referenced 2 times by $234d, $29c2
l2532
    !byte 4                                                           ; 2532: 04          .
; $2533 referenced 2 times by $2382, $29e2
l2533
    !byte $1b                                                         ; 2533: 1b          .
; $2534 referenced 2 times by $2388, $29e8
l2534
    !byte 4                                                           ; 2534: 04          .
; $2535 referenced 2 times by $23bd, $2a08
l2535
    !byte $25                                                         ; 2535: 25          %
; $2536 referenced 2 times by $23c3, $2a0e
l2536
    !byte 4                                                           ; 2536: 04          .
; $2537 referenced 2 times by $23f8, $2a2e
l2537
    !byte $2f                                                         ; 2537: 2f          /
; $2538 referenced 2 times by $23fe, $2a34
l2538
    !byte 4                                                           ; 2538: 04          .
; $2539 referenced 2 times by $2433, $2a54
l2539
    !byte $39                                                         ; 2539: 39          9
; $253a referenced 2 times by $2439, $2a5a
l253a
    !byte 4                                                           ; 253a: 04          .
; $253b referenced 2 times by $246e, $2a7a
l253b
    !byte $43                                                         ; 253b: 43          c
; $253c referenced 2 times by $2474, $2a80
l253c
    !byte 4                                                           ; 253c: 04          .
; $253d referenced 2 times by $24a9, $2aa0
l253d
    !byte $4d                                                         ; 253d: 4d          m
; $253e referenced 2 times by $24af, $2aa6
l253e
    !byte 4                                                           ; 253e: 04          .
; $253f referenced 1 time by $24e4
l253f
    !byte $57                                                         ; 253f: 57          w
; $2540 referenced 1 time by $24ea
l2540
    !byte 4                                                           ; 2540: 04          .
; $2541 referenced 2 times by $27de, $27f9
special_card_face_array
    !byte 0                                                           ; 2541: 00          .
; $2542 referenced 2 times by $27e4, $27ff
l2542
    !byte $10                                                         ; 2542: 10          .
; $2543 referenced 2 times by $276f, $27a6
l2543
    !byte $40                                                         ; 2543: 40          @
; $2544 referenced 2 times by $2775, $27ac
l2544
    !byte $10                                                         ; 2544: 10          .
card_face_origin
    !byte $80, $10,   1, 0, $c0, $10, $fe, 0,   0, $11,   2, 0        ; 2545: 80 10 01... ...
    !byte $40, $11, $fd, 0, $80, $11,   3, 0, $c0, $11, $fc, 0        ; 2551: 40 11 fd... @..
    !byte   0, $12,   4, 0, $40, $12, $fb, 0, $80, $12,   5, 0        ; 255d: 00 12 04... ...
    !byte $c0, $12, $fa, 0,   0, $13,   6, 0, $40, $13, $f9, 0        ; 2569: c0 12 fa... ...
    !byte $80, $13,   7, 0, $c0, $13, $f8, 0,   0, $14,   8, 0        ; 2575: 80 13 07... ...
    !byte $40, $14, $f7, 0                                            ; 2581: 40 14 f7... @..

; $2585 referenced 1 time by $20f0
fill_unique_array
    ldx #$0f                                                          ; 2585: a2 0f       ..
    ldy #0                                                            ; 2587: a0 00       ..
; $2589 referenced 1 time by $258f
clear_used
    lda #0                                                            ; 2589: a9 00       ..
    sta used,x                                                        ; 258b: 9d bb 25    ..%
    dex                                                               ; 258e: ca          J
    bpl clear_used                                                    ; 258f: 10 f8       ..
; $2591 referenced 2 times by $259a, $25a8
fill_loop
    lda sid_voice3_oscillator                                         ; 2591: ad 1b d4    ..T
    and #$0f                                                          ; 2594: 29 0f       ).
    tax                                                               ; 2596: aa          .
    lda used,x                                                        ; 2597: bd bb 25    ..%
    bne fill_loop                                                     ; 259a: d0 f5       P.
    lda #1                                                            ; 259c: a9 01       ..
    sta used,x                                                        ; 259e: 9d bb 25    ..%
    txa                                                               ; 25a1: 8a          .
    sta array,y                                                       ; 25a2: 99 ab 25    ..%
    iny                                                               ; 25a5: c8          H
    cpy #$10                                                          ; 25a6: c0 10       ..
    bne fill_loop                                                     ; 25a8: d0 e7       P.
    rts                                                               ; 25aa: 60          .

; $25ab referenced 2 times by $25a2, $25df
array
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0              ; 25ab: 00 00 00... ...
; $25bb referenced 3 times by $258b, $2597, $259e
used
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0              ; 25bb: 00 00 00... ...

; $25cb referenced 1 time by $20f3
copy
    lda #$45 ; 'e'                                                    ; 25cb: a9 45       .e
    sta l00fa                                                         ; 25cd: 85 fa       ..
    lda #$25 ; '%'                                                    ; 25cf: a9 25       .%
    sta l00fb                                                         ; 25d1: 85 fb       ..
    lda #$15                                                          ; 25d3: a9 15       ..
    sta l00fc                                                         ; 25d5: 85 fc       ..
    lda #$26 ; '&'                                                    ; 25d7: a9 26       .&
    sta l00fd                                                         ; 25d9: 85 fd       ..
    ldy #0                                                            ; 25db: a0 00       ..
    ldx #0                                                            ; 25dd: a2 00       ..
; $25df referenced 1 time by $2612
out_loop
    lda array,x                                                       ; 25df: bd ab 25    ..%
    asl                                                               ; 25e2: 0a          .
    asl                                                               ; 25e3: 0a          .
    clc                                                               ; 25e4: 18          .
    adc l00fa                                                         ; 25e5: 65 fa       ..
    sta l00fa                                                         ; 25e7: 85 fa       ..
    lda #0                                                            ; 25e9: a9 00       ..
    adc l00fb                                                         ; 25eb: 65 fb       ..
    sta l00fb                                                         ; 25ed: 85 fb       ..
; $25ef referenced 1 time by $25f6
inner_loop
    lda (l00fa),y                                                     ; 25ef: b1 fa       ..
    sta (l00fc),y                                                     ; 25f1: 91 fc       ..
    iny                                                               ; 25f3: c8          H
    cpy #4                                                            ; 25f4: c0 04       ..
    bne inner_loop                                                    ; 25f6: d0 f7       P.
    ldy #0                                                            ; 25f8: a0 00       ..
inc_out_loop
    lda #4                                                            ; 25fa: a9 04       ..
    clc                                                               ; 25fc: 18          .
    adc l00fc                                                         ; 25fd: 65 fc       ..
    sta l00fc                                                         ; 25ff: 85 fc       ..
    lda #0                                                            ; 2601: a9 00       ..
    adc l00fd                                                         ; 2603: 65 fd       ..
    sta l00fd                                                         ; 2605: 85 fd       ..
    lda #$45 ; 'e'                                                    ; 2607: a9 45       .e
    sta l00fa                                                         ; 2609: 85 fa       ..
    lda #$25 ; '%'                                                    ; 260b: a9 25       .%
    sta l00fb                                                         ; 260d: 85 fb       ..
    inx                                                               ; 260f: e8          .
    cpx #$10                                                          ; 2610: e0 10       ..
    bne out_loop                                                      ; 2612: d0 cb       PK
    rts                                                               ; 2614: 60          .

; $2615 referenced 1 time by $2194
card_face_array
    !byte 0                                                           ; 2615: 00          .
; $2616 referenced 1 time by $219a
l2616
    !byte 0                                                           ; 2616: 00          .
; $2617 referenced 1 time by $21a0
l2617
    !byte 0, 0                                                        ; 2617: 00 00       ..
; $2619 referenced 1 time by $21cf
l2619
    !byte 0                                                           ; 2619: 00          .
; $261a referenced 1 time by $21d5
l261a
    !byte 0                                                           ; 261a: 00          .
; $261b referenced 1 time by $21db
l261b
    !byte 0, 0                                                        ; 261b: 00 00       ..
; $261d referenced 1 time by $220a
l261d
    !byte 0                                                           ; 261d: 00          .
; $261e referenced 1 time by $2210
l261e
    !byte 0                                                           ; 261e: 00          .
; $261f referenced 1 time by $2216
l261f
    !byte 0, 0                                                        ; 261f: 00 00       ..
; $2621 referenced 1 time by $2245
l2621
    !byte 0                                                           ; 2621: 00          .
; $2622 referenced 1 time by $224b
l2622
    !byte 0                                                           ; 2622: 00          .
; $2623 referenced 1 time by $2251
l2623
    !byte 0, 0                                                        ; 2623: 00 00       ..
; $2625 referenced 1 time by $2280
l2625
    !byte 0                                                           ; 2625: 00          .
; $2626 referenced 1 time by $2286
l2626
    !byte 0                                                           ; 2626: 00          .
; $2627 referenced 1 time by $228c
l2627
    !byte 0, 0                                                        ; 2627: 00 00       ..
; $2629 referenced 1 time by $22bb
l2629
    !byte 0                                                           ; 2629: 00          .
; $262a referenced 1 time by $22c1
l262a
    !byte 0                                                           ; 262a: 00          .
; $262b referenced 1 time by $22c7
l262b
    !byte 0, 0                                                        ; 262b: 00 00       ..
; $262d referenced 1 time by $22f6
l262d
    !byte 0                                                           ; 262d: 00          .
; $262e referenced 1 time by $22fc
l262e
    !byte 0                                                           ; 262e: 00          .
; $262f referenced 1 time by $2302
l262f
    !byte 0, 0                                                        ; 262f: 00 00       ..
; $2631 referenced 1 time by $2331
l2631
    !byte 0                                                           ; 2631: 00          .
; $2632 referenced 1 time by $2337
l2632
    !byte 0                                                           ; 2632: 00          .
; $2633 referenced 1 time by $233d
l2633
    !byte 0, 0                                                        ; 2633: 00 00       ..
; $2635 referenced 1 time by $236c
l2635
    !byte 0                                                           ; 2635: 00          .
; $2636 referenced 1 time by $2372
l2636
    !byte 0                                                           ; 2636: 00          .
; $2637 referenced 1 time by $2378
l2637
    !byte 0, 0                                                        ; 2637: 00 00       ..
; $2639 referenced 1 time by $23a7
l2639
    !byte 0                                                           ; 2639: 00          .
; $263a referenced 1 time by $23ad
l263a
    !byte 0                                                           ; 263a: 00          .
; $263b referenced 1 time by $23b3
l263b
    !byte 0, 0                                                        ; 263b: 00 00       ..
; $263d referenced 1 time by $23e2
l263d
    !byte 0                                                           ; 263d: 00          .
; $263e referenced 1 time by $23e8
l263e
    !byte 0                                                           ; 263e: 00          .
; $263f referenced 1 time by $23ee
l263f
    !byte 0, 0                                                        ; 263f: 00 00       ..
; $2641 referenced 1 time by $241d
l2641
    !byte 0                                                           ; 2641: 00          .
; $2642 referenced 1 time by $2423
l2642
    !byte 0                                                           ; 2642: 00          .
; $2643 referenced 1 time by $2429
l2643
    !byte 0, 0                                                        ; 2643: 00 00       ..
; $2645 referenced 1 time by $2458
l2645
    !byte 0                                                           ; 2645: 00          .
; $2646 referenced 1 time by $245e
l2646
    !byte 0                                                           ; 2646: 00          .
; $2647 referenced 1 time by $2464
l2647
    !byte 0, 0                                                        ; 2647: 00 00       ..
; $2649 referenced 1 time by $2493
l2649
    !byte 0                                                           ; 2649: 00          .
; $264a referenced 1 time by $2499
l264a
    !byte 0                                                           ; 264a: 00          .
; $264b referenced 1 time by $249f
l264b
    !byte 0, 0                                                        ; 264b: 00 00       ..
; $264d referenced 1 time by $24ce
l264d
    !byte 0                                                           ; 264d: 00          .
; $264e referenced 1 time by $24d4
l264e
    !byte 0                                                           ; 264e: 00          .
; $264f referenced 1 time by $24da
l264f
    !byte 0, 0                                                        ; 264f: 00 00       ..
; $2651 referenced 1 time by $2509
l2651
    !byte 0                                                           ; 2651: 00          .
; $2652 referenced 1 time by $250f
l2652
    !byte 0                                                           ; 2652: 00          .
; $2653 referenced 1 time by $2515
l2653
    !byte 0, 0                                                        ; 2653: 00 00       ..

; $2655 referenced 16 times by $21a6, $21e1, $221c, $2257, $2292, $22cd, $2308, $2343, $237e, $23b9, $23f4, $242f, $246a, $24a5, $24e0, $251b
display_card
    ldy #0                                                            ; 2655: a0 00       ..
    lda dst_low                                                       ; 2657: ad 02 20    ..
    sta l00fa                                                         ; 265a: 85 fa       ..
    lda dst_high                                                      ; 265c: ad 03 20    ..
    sta l00fb                                                         ; 265f: 85 fb       ..
    lda src_low                                                       ; 2661: ad 00 20    ..
    sta l00fc                                                         ; 2664: 85 fc       ..
    lda src_high                                                      ; 2666: ad 01 20    ..
    sta l00fd                                                         ; 2669: 85 fd       ..
    ldx #$18                                                          ; 266b: a2 18       ..
    jsr vdcin                                                         ; 266d: 20 da cd     ZM
    ora #$80                                                          ; 2670: 09 80       ..
    ldx #$18                                                          ; 2672: a2 18       ..
    jsr vdcout                                                        ; 2674: 20 cc cd     LM
; $2677 referenced 1 time by $26b7
c2677
    ldx #$12                                                          ; 2677: a2 12       ..
    lda l00fb                                                         ; 2679: a5 fb       ..
    jsr vdcout                                                        ; 267b: 20 cc cd     LM
    ldx #$13                                                          ; 267e: a2 13       ..
    lda l00fa                                                         ; 2680: a5 fa       ..
    jsr vdcout                                                        ; 2682: 20 cc cd     LM
    ldx #$20 ; ' '                                                    ; 2685: a2 20       .
    lda l00fd                                                         ; 2687: a5 fd       ..
    jsr vdcout                                                        ; 2689: 20 cc cd     LM
    ldx #$21 ; '!'                                                    ; 268c: a2 21       .!
    lda l00fc                                                         ; 268e: a5 fc       ..
    jsr vdcout                                                        ; 2690: 20 cc cd     LM
    ldx #$1e                                                          ; 2693: a2 1e       ..
    lda #8                                                            ; 2695: a9 08       ..
    jsr vdcout                                                        ; 2697: 20 cc cd     LM
    clc                                                               ; 269a: 18          .
    lda l00fa                                                         ; 269b: a5 fa       ..
    adc #$50 ; 'p'                                                    ; 269d: 69 50       .p
    sta l00fa                                                         ; 269f: 85 fa       ..
    lda l00fb                                                         ; 26a1: a5 fb       ..
    adc #0                                                            ; 26a3: 69 00       ..
    sta l00fb                                                         ; 26a5: 85 fb       ..
    clc                                                               ; 26a7: 18          .
    lda l00fc                                                         ; 26a8: a5 fc       ..
    adc #8                                                            ; 26aa: 69 08       ..
    sta l00fc                                                         ; 26ac: 85 fc       ..
    lda l00fd                                                         ; 26ae: a5 fd       ..
    adc #0                                                            ; 26b0: 69 00       ..
    sta l00fd                                                         ; 26b2: 85 fd       ..
    iny                                                               ; 26b4: c8          H
    cpy #8                                                            ; 26b5: c0 08       ..
    bne c2677                                                         ; 26b7: d0 be       P.
match_related
    inc match_cnt                                                     ; 26b9: ee 0d 20    ..
    lda match_cnt                                                     ; 26bc: ad 0d 20    ..
    cmp #1                                                            ; 26bf: c9 01       I.
    beq store_cord_1                                                  ; 26c1: f0 36       .6
    lda match_cnt                                                     ; 26c3: ad 0d 20    ..
    cmp #2                                                            ; 26c6: c9 02       I.
    beq store_cord_2                                                  ; 26c8: f0 42       .b
; $26ca referenced 1 time by $271e
return_from_store_cord_2
    lda value_1                                                       ; 26ca: ad 0e 20    ..
    cmp value_2                                                       ; 26cd: cd 0f 20    M.
    beq jsr_card_reset                                                ; 26d0: f0 1b       ..
    clc                                                               ; 26d2: 18          .
    adc value_2                                                       ; 26d3: 6d 0f 20    ..
    cmp #$ff                                                          ; 26d6: c9 ff       I.
    beq card_match                                                    ; 26d8: f0 47       .g
    lda score                                                         ; 26da: ad 10 20    ..
    sec                                                               ; 26dd: 38          8
    sbc #5                                                            ; 26de: e9 05       ..
    sta score                                                         ; 26e0: 8d 10 20    ..
    bmi set_score_to_zero                                             ; 26e3: 30 03       0.
    jmp jsr_card_reset                                                ; 26e5: 4c ed 26    l.&

; $26e8 referenced 1 time by $26e3
set_score_to_zero
    lda #0                                                            ; 26e8: a9 00       ..
    sta score                                                         ; 26ea: 8d 10 20    ..
; $26ed referenced 2 times by $26d0, $26e5
jsr_card_reset
    jsr card_reset                                                    ; 26ed: 20 b8 27     .'
; $26f0 referenced 1 time by $27b5
return_from_card_match
    lda #0                                                            ; 26f0: a9 00       ..
    sta match_cnt                                                     ; 26f2: 8d 0d 20    ..
    sta match                                                         ; 26f5: 8d 0c 20    ..
    rts                                                               ; 26f8: 60          .

; $26f9 referenced 1 time by $26c1
store_cord_1
    lda dst_low                                                       ; 26f9: ad 02 20    ..
    sta dst_low_crd1                                                  ; 26fc: 8d 06 20    ..
    lda dst_high                                                      ; 26ff: ad 03 20    ..
    sta dst_high_crd1                                                 ; 2702: 8d 07 20    ..
    lda match                                                         ; 2705: ad 0c 20    ..
    sta value_1                                                       ; 2708: 8d 0e 20    ..
    rts                                                               ; 270b: 60          .

; $270c referenced 1 time by $26c8
store_cord_2
    lda dst_low                                                       ; 270c: ad 02 20    ..
    sta dst_low_crd2                                                  ; 270f: 8d 0a 20    ..
    lda dst_high                                                      ; 2712: ad 03 20    ..
    sta dst_high_crd2                                                 ; 2715: 8d 0b 20    ..
    lda match                                                         ; 2718: ad 0c 20    ..
    sta value_2                                                       ; 271b: 8d 0f 20    ..
    jmp return_from_store_cord_2                                      ; 271e: 4c ca 26    lJ&

; $2721 referenced 1 time by $26d8
card_match
    jsr play_match_snd                                                ; 2721: 20 27 2c     ',
    lda score                                                         ; 2724: ad 10 20    ..
    clc                                                               ; 2727: 18          .
    adc #$19                                                          ; 2728: 69 19       ..
    sta score                                                         ; 272a: 8d 10 20    ..
    sei                                                               ; 272d: 78          .
    pha                                                               ; 272e: 48          h
    lda #0                                                            ; 272f: a9 00       ..
    sta cia1_tod_seconds                                              ; 2731: 8d 09 dc    ...
    sta cia1_tod_tenths                                               ; 2734: 8d 08 dc    ...
; $2737 referenced 1 time by $273c
loop_c2737
    lda cia1_tod_seconds                                              ; 2737: ad 09 dc    ...
    cmp #1                                                            ; 273a: c9 01       I.
    bne loop_c2737                                                    ; 273c: d0 f9       P.
; $273e referenced 1 time by $2743
loop_c273e
    lda cia1_tod_tenths                                               ; 273e: ad 08 dc    ...
    cmp #3                                                            ; 2741: c9 03       I.
    bne loop_c273e                                                    ; 2743: d0 f9       P.
    pla                                                               ; 2745: 68          .
    cli                                                               ; 2746: 58          x
    lda dst_low_crd1                                                  ; 2747: ad 06 20    ..
    sta dst_low                                                       ; 274a: 8d 02 20    ..
    lda dst_high_crd1                                                 ; 274d: ad 07 20    ..
    sta dst_high                                                      ; 2750: 8d 03 20    ..
    ldx #$13                                                          ; 2753: a2 13       ..
    clc                                                               ; 2755: 18          .
    lda dst_low                                                       ; 2756: ad 02 20    ..
    adc #$d3 ; 'S'                                                    ; 2759: 69 d3       .S
    jsr vdcout                                                        ; 275b: 20 cc cd     LM
    ldx #$12                                                          ; 275e: a2 12       ..
    lda dst_high                                                      ; 2760: ad 03 20    ..
    adc #2                                                            ; 2763: 69 02       ..
    jsr vdcout                                                        ; 2765: 20 cc cd     LM
    lda #$20 ; ' '                                                    ; 2768: a9 20       .
    ldx #$1f                                                          ; 276a: a2 1f       ..
    jsr vdcout                                                        ; 276c: 20 cc cd     LM
    lda l2543                                                         ; 276f: ad 43 25    .c%
    sta src_low                                                       ; 2772: 8d 00 20    ..
    lda l2544                                                         ; 2775: ad 44 25    .d%
    sta src_high                                                      ; 2778: 8d 01 20    ..
    jsr reset_card                                                    ; 277b: 20 09 28     .(
    lda dst_low_crd2                                                  ; 277e: ad 0a 20    ..
    sta dst_low                                                       ; 2781: 8d 02 20    ..
    lda dst_high_crd2                                                 ; 2784: ad 0b 20    ..
    sta dst_high                                                      ; 2787: 8d 03 20    ..
    ldx #$13                                                          ; 278a: a2 13       ..
    clc                                                               ; 278c: 18          .
    lda dst_low                                                       ; 278d: ad 02 20    ..
    adc #$d3 ; 'S'                                                    ; 2790: 69 d3       .S
    jsr vdcout                                                        ; 2792: 20 cc cd     LM
    ldx #$12                                                          ; 2795: a2 12       ..
    lda dst_high                                                      ; 2797: ad 03 20    ..
    adc #2                                                            ; 279a: 69 02       ..
    jsr vdcout                                                        ; 279c: 20 cc cd     LM
    lda #$20 ; ' '                                                    ; 279f: a9 20       .
    ldx #$1f                                                          ; 27a1: a2 1f       ..
    jsr vdcout                                                        ; 27a3: 20 cc cd     LM
    lda l2543                                                         ; 27a6: ad 43 25    .c%
    sta src_low                                                       ; 27a9: 8d 00 20    ..
    lda l2544                                                         ; 27ac: ad 44 25    .d%
    sta src_high                                                      ; 27af: 8d 01 20    ..
    jsr reset_card                                                    ; 27b2: 20 09 28     .(
    jmp return_from_card_match                                        ; 27b5: 4c f0 26    l.&

; $27b8 referenced 1 time by $26ed
card_reset
    sei                                                               ; 27b8: 78          .
    pha                                                               ; 27b9: 48          h
    lda #0                                                            ; 27ba: a9 00       ..
    sta cia1_tod_seconds                                              ; 27bc: 8d 09 dc    ...
    sta cia1_tod_tenths                                               ; 27bf: 8d 08 dc    ...
; $27c2 referenced 1 time by $27c7
loop_c27c2
    lda cia1_tod_seconds                                              ; 27c2: ad 09 dc    ...
    cmp #1                                                            ; 27c5: c9 01       I.
    bne loop_c27c2                                                    ; 27c7: d0 f9       P.
; $27c9 referenced 1 time by $27ce
loop_c27c9
    lda cia1_tod_tenths                                               ; 27c9: ad 08 dc    ...
    cmp #3                                                            ; 27cc: c9 03       I.
    bne loop_c27c9                                                    ; 27ce: d0 f9       P.
    pla                                                               ; 27d0: 68          .
    cli                                                               ; 27d1: 58          x
    lda dst_low_crd1                                                  ; 27d2: ad 06 20    ..
    sta dst_low                                                       ; 27d5: 8d 02 20    ..
    lda dst_high_crd1                                                 ; 27d8: ad 07 20    ..
    sta dst_high                                                      ; 27db: 8d 03 20    ..
    lda special_card_face_array                                       ; 27de: ad 41 25    .a%
    sta src_low                                                       ; 27e1: 8d 00 20    ..
    lda l2542                                                         ; 27e4: ad 42 25    .b%
    sta src_high                                                      ; 27e7: 8d 01 20    ..
    jsr reset_card                                                    ; 27ea: 20 09 28     .(
    lda dst_low_crd2                                                  ; 27ed: ad 0a 20    ..
    sta dst_low                                                       ; 27f0: 8d 02 20    ..
    lda dst_high_crd2                                                 ; 27f3: ad 0b 20    ..
    sta dst_high                                                      ; 27f6: 8d 03 20    ..
    lda special_card_face_array                                       ; 27f9: ad 41 25    .a%
    sta src_low                                                       ; 27fc: 8d 00 20    ..
    lda l2542                                                         ; 27ff: ad 42 25    .b%
    sta src_high                                                      ; 2802: 8d 01 20    ..
    jsr reset_card                                                    ; 2805: 20 09 28     .(
    rts                                                               ; 2808: 60          .

; $2809 referenced 4 times by $277b, $27b2, $27ea, $2805
reset_card
    ldy #0                                                            ; 2809: a0 00       ..
    ldx #$18                                                          ; 280b: a2 18       ..
    jsr vdcin                                                         ; 280d: 20 da cd     ZM
    ora #$80                                                          ; 2810: 09 80       ..
    ldx #$18                                                          ; 2812: a2 18       ..
    jsr vdcout                                                        ; 2814: 20 cc cd     LM
; $2817 referenced 1 time by $2863
c2817
    ldx #$12                                                          ; 2817: a2 12       ..
    lda dst_high                                                      ; 2819: ad 03 20    ..
    jsr vdcout                                                        ; 281c: 20 cc cd     LM
    ldx #$13                                                          ; 281f: a2 13       ..
    lda dst_low                                                       ; 2821: ad 02 20    ..
    jsr vdcout                                                        ; 2824: 20 cc cd     LM
    ldx #$20 ; ' '                                                    ; 2827: a2 20       .
    lda src_high                                                      ; 2829: ad 01 20    ..
    jsr vdcout                                                        ; 282c: 20 cc cd     LM
    ldx #$21 ; '!'                                                    ; 282f: a2 21       .!
    lda src_low                                                       ; 2831: ad 00 20    ..
    jsr vdcout                                                        ; 2834: 20 cc cd     LM
    ldx #$1e                                                          ; 2837: a2 1e       ..
    lda #8                                                            ; 2839: a9 08       ..
    jsr vdcout                                                        ; 283b: 20 cc cd     LM
    clc                                                               ; 283e: 18          .
    lda dst_low                                                       ; 283f: ad 02 20    ..
    adc #$50 ; 'p'                                                    ; 2842: 69 50       .p
    sta dst_low                                                       ; 2844: 8d 02 20    ..
    lda dst_high                                                      ; 2847: ad 03 20    ..
    adc #0                                                            ; 284a: 69 00       ..
    sta dst_high                                                      ; 284c: 8d 03 20    ..
    clc                                                               ; 284f: 18          .
    lda src_low                                                       ; 2850: ad 00 20    ..
    adc #8                                                            ; 2853: 69 08       ..
    sta src_low                                                       ; 2855: 8d 00 20    ..
    lda src_high                                                      ; 2858: ad 01 20    ..
    adc #0                                                            ; 285b: 69 00       ..
    sta src_high                                                      ; 285d: 8d 01 20    ..
    iny                                                               ; 2860: c8          H
    cpy #8                                                            ; 2861: c0 08       ..
    bne c2817                                                         ; 2863: d0 b2       P.
    rts                                                               ; 2865: 60          .

; $2866 referenced 1 time by $20f9
check_no_cards
    lda card_pos_array                                                ; 2866: ad 1f 25    ..%
    sta dst_low                                                       ; 2869: 8d 02 20    ..
    lda l2520                                                         ; 286c: ad 20 25    . %
    sta dst_high                                                      ; 286f: 8d 03 20    ..
    ldx #$12                                                          ; 2872: a2 12       ..
    lda dst_high                                                      ; 2874: ad 03 20    ..
    jsr vdcout                                                        ; 2877: 20 cc cd     LM
    ldx #$13                                                          ; 287a: a2 13       ..
    lda dst_low                                                       ; 287c: ad 02 20    ..
    jsr vdcout                                                        ; 287f: 20 cc cd     LM
    ldx #$1f                                                          ; 2882: a2 1f       ..
    jsr vdcin                                                         ; 2884: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2887: c9 20       I
    beq c288c                                                         ; 2889: f0 01       ..
    rts                                                               ; 288b: 60          .

; $288c referenced 1 time by $2889
c288c
    lda l2521                                                         ; 288c: ad 21 25    .!%
    sta dst_low                                                       ; 288f: 8d 02 20    ..
    lda l2522                                                         ; 2892: ad 22 25    ."%
    sta dst_high                                                      ; 2895: 8d 03 20    ..
    ldx #$12                                                          ; 2898: a2 12       ..
    lda dst_high                                                      ; 289a: ad 03 20    ..
    jsr vdcout                                                        ; 289d: 20 cc cd     LM
    ldx #$13                                                          ; 28a0: a2 13       ..
    lda dst_low                                                       ; 28a2: ad 02 20    ..
    jsr vdcout                                                        ; 28a5: 20 cc cd     LM
    ldx #$1f                                                          ; 28a8: a2 1f       ..
    jsr vdcin                                                         ; 28aa: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 28ad: c9 20       I
    beq c28b2                                                         ; 28af: f0 01       ..
    rts                                                               ; 28b1: 60          .

; $28b2 referenced 1 time by $28af
c28b2
    lda l2523                                                         ; 28b2: ad 23 25    .#%
    sta dst_low                                                       ; 28b5: 8d 02 20    ..
    lda l2524                                                         ; 28b8: ad 24 25    .$%
    sta dst_high                                                      ; 28bb: 8d 03 20    ..
    ldx #$12                                                          ; 28be: a2 12       ..
    lda dst_high                                                      ; 28c0: ad 03 20    ..
    jsr vdcout                                                        ; 28c3: 20 cc cd     LM
    ldx #$13                                                          ; 28c6: a2 13       ..
    lda dst_low                                                       ; 28c8: ad 02 20    ..
    jsr vdcout                                                        ; 28cb: 20 cc cd     LM
    ldx #$1f                                                          ; 28ce: a2 1f       ..
    jsr vdcin                                                         ; 28d0: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 28d3: c9 20       I
    beq c28d8                                                         ; 28d5: f0 01       ..
    rts                                                               ; 28d7: 60          .

; $28d8 referenced 1 time by $28d5
c28d8
    lda l2525                                                         ; 28d8: ad 25 25    .%%
    sta dst_low                                                       ; 28db: 8d 02 20    ..
    lda l2526                                                         ; 28de: ad 26 25    .&%
    sta dst_high                                                      ; 28e1: 8d 03 20    ..
    ldx #$12                                                          ; 28e4: a2 12       ..
    lda dst_high                                                      ; 28e6: ad 03 20    ..
    jsr vdcout                                                        ; 28e9: 20 cc cd     LM
    ldx #$13                                                          ; 28ec: a2 13       ..
    lda dst_low                                                       ; 28ee: ad 02 20    ..
    jsr vdcout                                                        ; 28f1: 20 cc cd     LM
    ldx #$1f                                                          ; 28f4: a2 1f       ..
    jsr vdcin                                                         ; 28f6: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 28f9: c9 20       I
    beq c28fe                                                         ; 28fb: f0 01       ..
    rts                                                               ; 28fd: 60          .

; $28fe referenced 1 time by $28fb
c28fe
    lda l2527                                                         ; 28fe: ad 27 25    .'%
    sta dst_low                                                       ; 2901: 8d 02 20    ..
    lda l2528                                                         ; 2904: ad 28 25    .(%
    sta dst_high                                                      ; 2907: 8d 03 20    ..
    ldx #$12                                                          ; 290a: a2 12       ..
    lda dst_high                                                      ; 290c: ad 03 20    ..
    jsr vdcout                                                        ; 290f: 20 cc cd     LM
    ldx #$13                                                          ; 2912: a2 13       ..
    lda dst_low                                                       ; 2914: ad 02 20    ..
    jsr vdcout                                                        ; 2917: 20 cc cd     LM
    ldx #$1f                                                          ; 291a: a2 1f       ..
    jsr vdcin                                                         ; 291c: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 291f: c9 20       I
    beq c2924                                                         ; 2921: f0 01       ..
    rts                                                               ; 2923: 60          .

; $2924 referenced 1 time by $2921
c2924
    lda l2529                                                         ; 2924: ad 29 25    .)%
    sta dst_low                                                       ; 2927: 8d 02 20    ..
    lda l252a                                                         ; 292a: ad 2a 25    .*%
    sta dst_high                                                      ; 292d: 8d 03 20    ..
    ldx #$12                                                          ; 2930: a2 12       ..
    lda dst_high                                                      ; 2932: ad 03 20    ..
    jsr vdcout                                                        ; 2935: 20 cc cd     LM
    ldx #$13                                                          ; 2938: a2 13       ..
    lda dst_low                                                       ; 293a: ad 02 20    ..
    jsr vdcout                                                        ; 293d: 20 cc cd     LM
    ldx #$1f                                                          ; 2940: a2 1f       ..
    jsr vdcin                                                         ; 2942: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2945: c9 20       I
    beq c294a                                                         ; 2947: f0 01       ..
    rts                                                               ; 2949: 60          .

; $294a referenced 1 time by $2947
c294a
    lda l252b                                                         ; 294a: ad 2b 25    .+%
    sta dst_low                                                       ; 294d: 8d 02 20    ..
    lda l252c                                                         ; 2950: ad 2c 25    .,%
    sta dst_high                                                      ; 2953: 8d 03 20    ..
    ldx #$12                                                          ; 2956: a2 12       ..
    lda dst_high                                                      ; 2958: ad 03 20    ..
    jsr vdcout                                                        ; 295b: 20 cc cd     LM
    ldx #$13                                                          ; 295e: a2 13       ..
    lda dst_low                                                       ; 2960: ad 02 20    ..
    jsr vdcout                                                        ; 2963: 20 cc cd     LM
    ldx #$1f                                                          ; 2966: a2 1f       ..
    jsr vdcin                                                         ; 2968: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 296b: c9 20       I
    beq c2970                                                         ; 296d: f0 01       ..
    rts                                                               ; 296f: 60          .

; $2970 referenced 1 time by $296d
c2970
    lda l252d                                                         ; 2970: ad 2d 25    .-%
    sta dst_low                                                       ; 2973: 8d 02 20    ..
    lda l252e                                                         ; 2976: ad 2e 25    ..%
    sta dst_high                                                      ; 2979: 8d 03 20    ..
    ldx #$12                                                          ; 297c: a2 12       ..
    lda dst_high                                                      ; 297e: ad 03 20    ..
    jsr vdcout                                                        ; 2981: 20 cc cd     LM
    ldx #$13                                                          ; 2984: a2 13       ..
    lda dst_low                                                       ; 2986: ad 02 20    ..
    jsr vdcout                                                        ; 2989: 20 cc cd     LM
    ldx #$1f                                                          ; 298c: a2 1f       ..
    jsr vdcin                                                         ; 298e: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2991: c9 20       I
    beq c2996                                                         ; 2993: f0 01       ..
    rts                                                               ; 2995: 60          .

; $2996 referenced 1 time by $2993
c2996
    lda l252f                                                         ; 2996: ad 2f 25    ./%
    sta dst_low                                                       ; 2999: 8d 02 20    ..
    lda l2530                                                         ; 299c: ad 30 25    .0%
    sta dst_high                                                      ; 299f: 8d 03 20    ..
    ldx #$12                                                          ; 29a2: a2 12       ..
    lda dst_high                                                      ; 29a4: ad 03 20    ..
    jsr vdcout                                                        ; 29a7: 20 cc cd     LM
    ldx #$13                                                          ; 29aa: a2 13       ..
    lda dst_low                                                       ; 29ac: ad 02 20    ..
    jsr vdcout                                                        ; 29af: 20 cc cd     LM
    ldx #$1f                                                          ; 29b2: a2 1f       ..
    jsr vdcin                                                         ; 29b4: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 29b7: c9 20       I
    beq c29bc                                                         ; 29b9: f0 01       ..
    rts                                                               ; 29bb: 60          .

; $29bc referenced 1 time by $29b9
c29bc
    lda l2531                                                         ; 29bc: ad 31 25    .1%
    sta dst_low                                                       ; 29bf: 8d 02 20    ..
    lda l2532                                                         ; 29c2: ad 32 25    .2%
    sta dst_high                                                      ; 29c5: 8d 03 20    ..
    ldx #$12                                                          ; 29c8: a2 12       ..
    lda dst_high                                                      ; 29ca: ad 03 20    ..
    jsr vdcout                                                        ; 29cd: 20 cc cd     LM
    ldx #$13                                                          ; 29d0: a2 13       ..
    lda dst_low                                                       ; 29d2: ad 02 20    ..
    jsr vdcout                                                        ; 29d5: 20 cc cd     LM
    ldx #$1f                                                          ; 29d8: a2 1f       ..
    jsr vdcin                                                         ; 29da: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 29dd: c9 20       I
    beq c29e2                                                         ; 29df: f0 01       ..
    rts                                                               ; 29e1: 60          .

; $29e2 referenced 1 time by $29df
c29e2
    lda l2533                                                         ; 29e2: ad 33 25    .3%
    sta dst_low                                                       ; 29e5: 8d 02 20    ..
    lda l2534                                                         ; 29e8: ad 34 25    .4%
    sta dst_high                                                      ; 29eb: 8d 03 20    ..
    ldx #$12                                                          ; 29ee: a2 12       ..
    lda dst_high                                                      ; 29f0: ad 03 20    ..
    jsr vdcout                                                        ; 29f3: 20 cc cd     LM
    ldx #$13                                                          ; 29f6: a2 13       ..
    lda dst_low                                                       ; 29f8: ad 02 20    ..
    jsr vdcout                                                        ; 29fb: 20 cc cd     LM
    ldx #$1f                                                          ; 29fe: a2 1f       ..
    jsr vdcin                                                         ; 2a00: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2a03: c9 20       I
    beq c2a08                                                         ; 2a05: f0 01       ..
    rts                                                               ; 2a07: 60          .

; $2a08 referenced 1 time by $2a05
c2a08
    lda l2535                                                         ; 2a08: ad 35 25    .5%
    sta dst_low                                                       ; 2a0b: 8d 02 20    ..
    lda l2536                                                         ; 2a0e: ad 36 25    .6%
    sta dst_high                                                      ; 2a11: 8d 03 20    ..
    ldx #$12                                                          ; 2a14: a2 12       ..
    lda dst_high                                                      ; 2a16: ad 03 20    ..
    jsr vdcout                                                        ; 2a19: 20 cc cd     LM
    ldx #$13                                                          ; 2a1c: a2 13       ..
    lda dst_low                                                       ; 2a1e: ad 02 20    ..
    jsr vdcout                                                        ; 2a21: 20 cc cd     LM
    ldx #$1f                                                          ; 2a24: a2 1f       ..
    jsr vdcin                                                         ; 2a26: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2a29: c9 20       I
    beq c2a2e                                                         ; 2a2b: f0 01       ..
    rts                                                               ; 2a2d: 60          .

; $2a2e referenced 1 time by $2a2b
c2a2e
    lda l2537                                                         ; 2a2e: ad 37 25    .7%
    sta dst_low                                                       ; 2a31: 8d 02 20    ..
    lda l2538                                                         ; 2a34: ad 38 25    .8%
    sta dst_high                                                      ; 2a37: 8d 03 20    ..
    ldx #$12                                                          ; 2a3a: a2 12       ..
    lda dst_high                                                      ; 2a3c: ad 03 20    ..
    jsr vdcout                                                        ; 2a3f: 20 cc cd     LM
    ldx #$13                                                          ; 2a42: a2 13       ..
    lda dst_low                                                       ; 2a44: ad 02 20    ..
    jsr vdcout                                                        ; 2a47: 20 cc cd     LM
    ldx #$1f                                                          ; 2a4a: a2 1f       ..
    jsr vdcin                                                         ; 2a4c: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2a4f: c9 20       I
    beq c2a54                                                         ; 2a51: f0 01       ..
    rts                                                               ; 2a53: 60          .

; $2a54 referenced 1 time by $2a51
c2a54
    lda l2539                                                         ; 2a54: ad 39 25    .9%
    sta dst_low                                                       ; 2a57: 8d 02 20    ..
    lda l253a                                                         ; 2a5a: ad 3a 25    .:%
    sta dst_high                                                      ; 2a5d: 8d 03 20    ..
    ldx #$12                                                          ; 2a60: a2 12       ..
    lda dst_high                                                      ; 2a62: ad 03 20    ..
    jsr vdcout                                                        ; 2a65: 20 cc cd     LM
    ldx #$13                                                          ; 2a68: a2 13       ..
    lda dst_low                                                       ; 2a6a: ad 02 20    ..
    jsr vdcout                                                        ; 2a6d: 20 cc cd     LM
    ldx #$1f                                                          ; 2a70: a2 1f       ..
    jsr vdcin                                                         ; 2a72: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2a75: c9 20       I
    beq c2a7a                                                         ; 2a77: f0 01       ..
    rts                                                               ; 2a79: 60          .

; $2a7a referenced 1 time by $2a77
c2a7a
    lda l253b                                                         ; 2a7a: ad 3b 25    .;%
    sta dst_low                                                       ; 2a7d: 8d 02 20    ..
    lda l253c                                                         ; 2a80: ad 3c 25    .<%
    sta dst_high                                                      ; 2a83: 8d 03 20    ..
    ldx #$12                                                          ; 2a86: a2 12       ..
    lda dst_high                                                      ; 2a88: ad 03 20    ..
    jsr vdcout                                                        ; 2a8b: 20 cc cd     LM
    ldx #$13                                                          ; 2a8e: a2 13       ..
    lda dst_low                                                       ; 2a90: ad 02 20    ..
    jsr vdcout                                                        ; 2a93: 20 cc cd     LM
    ldx #$1f                                                          ; 2a96: a2 1f       ..
    jsr vdcin                                                         ; 2a98: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2a9b: c9 20       I
    beq c2aa0                                                         ; 2a9d: f0 01       ..
    rts                                                               ; 2a9f: 60          .

; $2aa0 referenced 1 time by $2a9d
c2aa0
    lda l253d                                                         ; 2aa0: ad 3d 25    .=%
    sta dst_low                                                       ; 2aa3: 8d 02 20    ..
    lda l253e                                                         ; 2aa6: ad 3e 25    .>%
    sta dst_high                                                      ; 2aa9: 8d 03 20    ..
    ldx #$12                                                          ; 2aac: a2 12       ..
    lda dst_high                                                      ; 2aae: ad 03 20    ..
    jsr vdcout                                                        ; 2ab1: 20 cc cd     LM
    ldx #$13                                                          ; 2ab4: a2 13       ..
    lda dst_low                                                       ; 2ab6: ad 02 20    ..
    jsr vdcout                                                        ; 2ab9: 20 cc cd     LM
    ldx #$1f                                                          ; 2abc: a2 1f       ..
    jsr vdcin                                                         ; 2abe: 20 da cd     ZM
    cmp #$20 ; ' '                                                    ; 2ac1: c9 20       I
    beq c2ac6                                                         ; 2ac3: f0 01       ..
    rts                                                               ; 2ac5: 60          .

; $2ac6 referenced 1 time by $2ac3
c2ac6
    jsr show_win                                                      ; 2ac6: 20 ca 2a     J*
    rts                                                               ; 2ac9: 60          .

; $2aca referenced 1 time by $2ac6
show_win
    ldx #$0c                                                          ; 2aca: a2 0c       ..
    lda #$18                                                          ; 2acc: a9 18       ..
    sta vdc_screen_base                                               ; 2ace: 8d 2e 0a    ...
    jsr vdcout                                                        ; 2ad1: 20 cc cd     LM
    ldx #$0d                                                          ; 2ad4: a2 0d       ..
    lda #0                                                            ; 2ad6: a9 00       ..
    jsr vdcout                                                        ; 2ad8: 20 cc cd     LM
    pha                                                               ; 2adb: 48          h
    lda #0                                                            ; 2adc: a9 00       ..
    sta jiffy_clock+2                                                 ; 2ade: 85 a2       ..
; $2ae0 referenced 1 time by $2ae4
loop_c2ae0
    lda jiffy_clock+2                                                 ; 2ae0: a5 a2       ..
    cmp #$3c ; '<'                                                    ; 2ae2: c9 3c       I<
    bne loop_c2ae0                                                    ; 2ae4: d0 fa       P.
    pla                                                               ; 2ae6: 68          .
    ldx #$0c                                                          ; 2ae7: a2 0c       ..
    lda #0                                                            ; 2ae9: a9 00       ..
    sta vdc_screen_base                                               ; 2aeb: 8d 2e 0a    ...
    jsr vdcout                                                        ; 2aee: 20 cc cd     LM
    ldx #$0d                                                          ; 2af1: a2 0d       ..
    lda #0                                                            ; 2af3: a9 00       ..
    jsr vdcout                                                        ; 2af5: 20 cc cd     LM
    pha                                                               ; 2af8: 48          h
    lda #0                                                            ; 2af9: a9 00       ..
    sta jiffy_clock+2                                                 ; 2afb: 85 a2       ..
; $2afd referenced 1 time by $2b01
loop_c2afd
    lda jiffy_clock+2                                                 ; 2afd: a5 a2       ..
    cmp #$3c ; '<'                                                    ; 2aff: c9 3c       I<
    bne loop_c2afd                                                    ; 2b01: d0 fa       P.
    pla                                                               ; 2b03: 68          .
    rts                                                               ; 2b04: 60          .

; $2b05 referenced 1 time by $20f6
decout
    lda score                                                         ; 2b05: ad 10 20    ..
    sta param                                                         ; 2b08: 8d 11 20    ..
    ldx #0                                                            ; 2b0b: a2 00       ..
    lda param                                                         ; 2b0d: ad 11 20    ..
    sec                                                               ; 2b10: 38          8
; $2b11 referenced 1 time by $2b19
decout_hund_loop
    sbc #$64                                                          ; 2b11: e9 64       ..
    bcc decout_hund_done                                              ; 2b13: 90 07       ..
    sta param                                                         ; 2b15: 8d 11 20    ..
    inx                                                               ; 2b18: e8          .
    jmp decout_hund_loop                                              ; 2b19: 4c 11 2b    l.+

; $2b1c referenced 1 time by $2b13
decout_hund_done
    txa                                                               ; 2b1c: 8a          .
    ora #$30 ; '0'                                                    ; 2b1d: 09 30       .0
    cmp #$30 ; '0'                                                    ; 2b1f: c9 30       I0
    bne c2b51                                                         ; 2b21: d0 2e       P.
    lda #$20 ; ' '                                                    ; 2b23: a9 20       .
    pha                                                               ; 2b25: 48          h
    ldx #$12                                                          ; 2b26: a2 12       ..
    lda #7                                                            ; 2b28: a9 07       ..
    jsr vdcout                                                        ; 2b2a: 20 cc cd     LM
    ldx #$13                                                          ; 2b2d: a2 13       ..
    lda #$87                                                          ; 2b2f: a9 87       ..
    jsr vdcout                                                        ; 2b31: 20 cc cd     LM
    pla                                                               ; 2b34: 68          .
    ldx #$1f                                                          ; 2b35: a2 1f       ..
    jsr vdcout                                                        ; 2b37: 20 cc cd     LM
    pha                                                               ; 2b3a: 48          h
    ldx #$12                                                          ; 2b3b: a2 12       ..
    lda #$1f                                                          ; 2b3d: a9 1f       ..
    jsr vdcout                                                        ; 2b3f: 20 cc cd     LM
    ldx #$13                                                          ; 2b42: a2 13       ..
    lda #$87                                                          ; 2b44: a9 87       ..
    jsr vdcout                                                        ; 2b46: 20 cc cd     LM
    pla                                                               ; 2b49: 68          .
    ldx #$1f                                                          ; 2b4a: a2 1f       ..
    jsr vdcout                                                        ; 2b4c: 20 cc cd     LM
    ldy #$11                                                          ; 2b4f: a0 11       ..
; $2b51 referenced 1 time by $2b21
c2b51
    pha                                                               ; 2b51: 48          h
    ldx #$12                                                          ; 2b52: a2 12       ..
    lda #7                                                            ; 2b54: a9 07       ..
    jsr vdcout                                                        ; 2b56: 20 cc cd     LM
    ldx #$13                                                          ; 2b59: a2 13       ..
    lda #$87                                                          ; 2b5b: a9 87       ..
    jsr vdcout                                                        ; 2b5d: 20 cc cd     LM
    pla                                                               ; 2b60: 68          .
    ldx #$1f                                                          ; 2b61: a2 1f       ..
    jsr vdcout                                                        ; 2b63: 20 cc cd     LM
    pha                                                               ; 2b66: 48          h
    ldx #$12                                                          ; 2b67: a2 12       ..
    lda #$1f                                                          ; 2b69: a9 1f       ..
    jsr vdcout                                                        ; 2b6b: 20 cc cd     LM
    ldx #$13                                                          ; 2b6e: a2 13       ..
    lda #$87                                                          ; 2b70: a9 87       ..
    jsr vdcout                                                        ; 2b72: 20 cc cd     LM
    pla                                                               ; 2b75: 68          .
    ldx #$1f                                                          ; 2b76: a2 1f       ..
    jsr vdcout                                                        ; 2b78: 20 cc cd     LM
    ldx #0                                                            ; 2b7b: a2 00       ..
    lda param                                                         ; 2b7d: ad 11 20    ..
    sec                                                               ; 2b80: 38          8
; $2b81 referenced 1 time by $2b89
decout_tens_loop
    sbc #$0a                                                          ; 2b81: e9 0a       ..
    bcc decout_tens_done                                              ; 2b83: 90 07       ..
    sta param                                                         ; 2b85: 8d 11 20    ..
    inx                                                               ; 2b88: e8          .
    jmp decout_tens_loop                                              ; 2b89: 4c 81 2b    l.+

; $2b8c referenced 1 time by $2b83
decout_tens_done
    txa                                                               ; 2b8c: 8a          .
    ora #$30 ; '0'                                                    ; 2b8d: 09 30       .0
    cmp #$30 ; '0'                                                    ; 2b8f: c9 30       I0
    bne c2bc5                                                         ; 2b91: d0 32       P2
    cpy #$11                                                          ; 2b93: c0 11       ..
    bne c2bc5                                                         ; 2b95: d0 2e       P.
    lda #$20 ; ' '                                                    ; 2b97: a9 20       .
    ldy #0                                                            ; 2b99: a0 00       ..
    pha                                                               ; 2b9b: 48          h
    ldx #$12                                                          ; 2b9c: a2 12       ..
    lda #7                                                            ; 2b9e: a9 07       ..
    jsr vdcout                                                        ; 2ba0: 20 cc cd     LM
    ldx #$13                                                          ; 2ba3: a2 13       ..
    lda #$88                                                          ; 2ba5: a9 88       ..
    jsr vdcout                                                        ; 2ba7: 20 cc cd     LM
    pla                                                               ; 2baa: 68          .
    ldx #$1f                                                          ; 2bab: a2 1f       ..
    jsr vdcout                                                        ; 2bad: 20 cc cd     LM
    pha                                                               ; 2bb0: 48          h
    ldx #$12                                                          ; 2bb1: a2 12       ..
    lda #$1f                                                          ; 2bb3: a9 1f       ..
    jsr vdcout                                                        ; 2bb5: 20 cc cd     LM
    ldx #$13                                                          ; 2bb8: a2 13       ..
    lda #$88                                                          ; 2bba: a9 88       ..
    jsr vdcout                                                        ; 2bbc: 20 cc cd     LM
    pla                                                               ; 2bbf: 68          .
    ldx #$1f                                                          ; 2bc0: a2 1f       ..
    jsr vdcout                                                        ; 2bc2: 20 cc cd     LM
; $2bc5 referenced 2 times by $2b91, $2b95
c2bc5
    pha                                                               ; 2bc5: 48          h
    ldx #$12                                                          ; 2bc6: a2 12       ..
    lda #7                                                            ; 2bc8: a9 07       ..
    jsr vdcout                                                        ; 2bca: 20 cc cd     LM
    ldx #$13                                                          ; 2bcd: a2 13       ..
    lda #$88                                                          ; 2bcf: a9 88       ..
    jsr vdcout                                                        ; 2bd1: 20 cc cd     LM
    pla                                                               ; 2bd4: 68          .
    ldx #$1f                                                          ; 2bd5: a2 1f       ..
    jsr vdcout                                                        ; 2bd7: 20 cc cd     LM
    pha                                                               ; 2bda: 48          h
    ldx #$12                                                          ; 2bdb: a2 12       ..
    lda #$1f                                                          ; 2bdd: a9 1f       ..
    jsr vdcout                                                        ; 2bdf: 20 cc cd     LM
    ldx #$13                                                          ; 2be2: a2 13       ..
    lda #$88                                                          ; 2be4: a9 88       ..
    jsr vdcout                                                        ; 2be6: 20 cc cd     LM
    pla                                                               ; 2be9: 68          .
    ldx #$1f                                                          ; 2bea: a2 1f       ..
    jsr vdcout                                                        ; 2bec: 20 cc cd     LM
    lda param                                                         ; 2bef: ad 11 20    ..
    ora #$30 ; '0'                                                    ; 2bf2: 09 30       .0
    pha                                                               ; 2bf4: 48          h
    ldx #$12                                                          ; 2bf5: a2 12       ..
    lda #7                                                            ; 2bf7: a9 07       ..
    jsr vdcout                                                        ; 2bf9: 20 cc cd     LM
    ldx #$13                                                          ; 2bfc: a2 13       ..
    lda #$89                                                          ; 2bfe: a9 89       ..
    jsr vdcout                                                        ; 2c00: 20 cc cd     LM
    pla                                                               ; 2c03: 68          .
    ldx #$1f                                                          ; 2c04: a2 1f       ..
    jsr vdcout                                                        ; 2c06: 20 cc cd     LM
    pha                                                               ; 2c09: 48          h
    ldx #$12                                                          ; 2c0a: a2 12       ..
    lda #$1f                                                          ; 2c0c: a9 1f       ..
    jsr vdcout                                                        ; 2c0e: 20 cc cd     LM
    ldx #$13                                                          ; 2c11: a2 13       ..
    lda #$89                                                          ; 2c13: a9 89       ..
    jsr vdcout                                                        ; 2c15: 20 cc cd     LM
    pla                                                               ; 2c18: 68          .
    ldx #$1f                                                          ; 2c19: a2 1f       ..
    jsr vdcout                                                        ; 2c1b: 20 cc cd     LM
    rts                                                               ; 2c1e: 60          .

; $2c1f referenced 2 times by $2c42, $2c49
freqs
    !byte 0, $22, 0, $33, 0, $44, 0, $55                              ; 2c1f: 00 22 00... .".

; $2c27 referenced 1 time by $2721
play_match_snd
    lda #$8f                                                          ; 2c27: a9 8f       ..
    sta sid_volume_filter_mode                                        ; 2c29: 8d 18 d4    ..T
    lda #0                                                            ; 2c2c: a9 00       ..
    sta sid_voice1_pulse_width_low                                    ; 2c2e: 8d 02 d4    ..T
    lda #8                                                            ; 2c31: a9 08       ..
    sta sid_voice1_pulse_width_high                                   ; 2c33: 8d 03 d4    ..T
    lda #$10                                                          ; 2c36: a9 10       ..
    sta sid_voice1_attack_decay                                       ; 2c38: 8d 05 d4    ..T
    lda #$10                                                          ; 2c3b: a9 10       ..
    sta sid_voice1_sustain_release                                    ; 2c3d: 8d 06 d4    ..T
    ldx #0                                                            ; 2c40: a2 00       ..
; $2c42 referenced 1 time by $2c76
play_loop
    lda freqs,x                                                       ; 2c42: bd 1f 2c    ..,
    sta sid_voice1_frequency_low                                      ; 2c45: 8d 00 d4    ..T
    inx                                                               ; 2c48: e8          .
    lda freqs,x                                                       ; 2c49: bd 1f 2c    ..,
    sta sid_voice1_frequency_high                                     ; 2c4c: 8d 01 d4    ..T
    inx                                                               ; 2c4f: e8          .
    lda #$41 ; 'a'                                                    ; 2c50: a9 41       .a
    sta sid_voice1_control                                            ; 2c52: 8d 04 d4    ..T
    sei                                                               ; 2c55: 78          .
    pha                                                               ; 2c56: 48          h
    lda #0                                                            ; 2c57: a9 00       ..
    sta cia1_tod_seconds                                              ; 2c59: 8d 09 dc    ...
    sta cia1_tod_tenths                                               ; 2c5c: 8d 08 dc    ...
; $2c5f referenced 1 time by $2c64
loop_c2c5f
    lda cia1_tod_seconds                                              ; 2c5f: ad 09 dc    ...
    cmp #0                                                            ; 2c62: c9 00       I.
    bne loop_c2c5f                                                    ; 2c64: d0 f9       P.
; $2c66 referenced 1 time by $2c6b
loop_c2c66
    lda cia1_tod_tenths                                               ; 2c66: ad 08 dc    ...
    cmp #2                                                            ; 2c69: c9 02       I.
    bne loop_c2c66                                                    ; 2c6b: d0 f9       P.
    pla                                                               ; 2c6d: 68          .
    cli                                                               ; 2c6e: 58          x
    lda #$40 ; '@'                                                    ; 2c6f: a9 40       .@
    sta sid_voice1_control                                            ; 2c71: 8d 04 d4    ..T
    cpx #8                                                            ; 2c74: e0 08       ..
    bne play_loop                                                     ; 2c76: d0 ca       PJ
    lda #$80                                                          ; 2c78: a9 80       ..
    sta sid_volume_filter_mode                                        ; 2c7a: 8d 18 d4    ..T
    rts                                                               ; 2c7d: 60          .

    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2c7e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2c92: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2ca6: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2cba: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2cce: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2ce2: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2cf6: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d0a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d1e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d32: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d46: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d5a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d6e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d82: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2d96: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2daa: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2dbe: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2dd2: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2de6: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2dfa: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e0e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e22: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e36: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e4a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e5e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e72: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e86: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2e9a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2eae: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2ec2: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2ed6: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2eea: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2efe: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f12: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f26: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f3a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f4e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f62: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f76: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f8a: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2f9e: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2fb2: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2fc6: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 2fda: 00 00 00... ...
    !byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0        ; 2fee: 00 00 00... ...
chr_data
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3000: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3010: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3020: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3030: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3040: 20 20 20...
    !byte $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd; 3050: 20 cd a0...  M.
    !byte $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd; 3060: a0 a0 ce... ..N
    !byte $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0; 3070: a0 a0 ce... ..N
    !byte $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0; 3080: ce 20 20... N
    !byte $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20; 3090: ce cd a0... NM.
    !byte $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0; 30a0: 20 a0 cd...  .M
    !byte $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0; 30b0: cd ce a0... MN.
    !byte $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce; 30c0: cd ce a0... MN.
    !byte $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce; 30d0: a0 20 20... .
    !byte $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20; 30e0: a0 a0 cd... ..M
    !byte $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0; 30f0: 20 a0 ce...  .N
    !byte $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0; 3100: ce cd a0... NM.
    !byte $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd; 3110: ce cd a0... NM.
    !byte $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd; 3120: a0 20 20... .
    !byte $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20; 3130: a0 a0 ce... ..N
    !byte $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce; 3140: 20 ce a0...  N.
    !byte $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce; 3150: a0 a0 cd... ..M
    !byte $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0; 3160: a0 a0 cd... ..M
    !byte $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0; 3170: cd 20 20... M
    !byte $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20; 3180: cd ce a0... MN.
    !byte $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd; 3190: 20 cd a0...  M.
    !byte $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd; 31a0: a0 a0 ce... ..N
    !byte $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0; 31b0: a0 a0 ce... ..N
    !byte $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0; 31c0: ce 20 20... N
    !byte $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20; 31d0: ce cd a0... NM.
    !byte $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0; 31e0: 20 a0 cd...  .M
    !byte $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0; 31f0: cd ce a0... MN.
    !byte $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce; 3200: cd ce a0... MN.
    !byte $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce; 3210: a0 20 20... .
    !byte $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20; 3220: a0 a0 cd... ..M
    !byte $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0; 3230: 20 a0 ce...  .N
    !byte $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0; 3240: ce cd a0... NM.
    !byte $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd; 3250: ce cd a0... NM.
    !byte $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd; 3260: a0 20 20... .
    !byte $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20; 3270: a0 a0 ce... ..N
    !byte $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce; 3280: 20 ce a0...  N.
    !byte $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce; 3290: a0 a0 cd... ..M
    !byte $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0; 32a0: a0 a0 cd... ..M
    !byte $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0; 32b0: cd 20 20... M
    !byte $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20; 32c0: cd ce a0... MN.
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 32d0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 32e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 32f0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3300: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3310: 20 20 20...
    !byte $20, $20, $20, $20, $31, $20, $20, $20, $20, $20, $20, $20, $20, $20, $32, $20; 3320: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $33, $20, $20, $20, $20, $20, $20, $20; 3330: 20 20 20...
    !byte $20, $20, $34, $20, $20, $20, $20, $20, $20, $20, $20, $20, $35, $20, $20, $20; 3340: 20 20 34...   4
    !byte $20, $20, $20, $20, $20, $20, $36, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3350: 20 20 20...
    !byte $37, $20, $20, $20, $20, $20, $20, $20, $20, $20, $38, $20, $20, $20, $20, $20; 3360: 37 20 20... 7
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3370: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3380: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3390: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33c0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33d0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 33f0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3400: 20 20 20...
    !byte $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd; 3410: 20 cd a0...  M.
    !byte $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd; 3420: a0 a0 ce... ..N
    !byte $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0; 3430: a0 a0 ce... ..N
    !byte $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0; 3440: ce 20 20... N
    !byte $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20; 3450: ce cd a0... NM.
    !byte $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0; 3460: 20 a0 cd...  .M
    !byte $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0; 3470: cd ce a0... MN.
    !byte $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce; 3480: cd ce a0... MN.
    !byte $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce; 3490: a0 20 20... .
    !byte $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20; 34a0: a0 a0 cd... ..M
    !byte $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0; 34b0: 20 a0 ce...  .N
    !byte $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0; 34c0: ce cd a0... NM.
    !byte $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd; 34d0: ce cd a0... NM.
    !byte $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd; 34e0: a0 20 20... .
    !byte $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20; 34f0: a0 a0 ce... ..N
    !byte $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce; 3500: 20 ce a0...  N.
    !byte $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce; 3510: a0 a0 cd... ..M
    !byte $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0; 3520: a0 a0 cd... ..M
    !byte $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0; 3530: cd 20 20... M
    !byte $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20; 3540: cd ce a0... MN.
    !byte $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd; 3550: 20 cd a0...  M.
    !byte $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd; 3560: a0 a0 ce... ..N
    !byte $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0; 3570: a0 a0 ce... ..N
    !byte $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0; 3580: ce 20 20... N
    !byte $ce, $cd, $a0, $a0, $ce, $20, $20, $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $20; 3590: ce cd a0... NM.
    !byte $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0; 35a0: 20 a0 cd...  .M
    !byte $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0; 35b0: cd ce a0... MN.
    !byte $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce; 35c0: cd ce a0... MN.
    !byte $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce; 35d0: a0 20 20... .
    !byte $a0, $a0, $cd, $ce, $a0, $20, $20, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0, $20; 35e0: a0 a0 cd... ..M
    !byte $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0; 35f0: 20 a0 ce...  .N
    !byte $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0; 3600: ce cd a0... NM.
    !byte $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd; 3610: ce cd a0... NM.
    !byte $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd; 3620: a0 20 20... .
    !byte $a0, $a0, $ce, $cd, $a0, $20, $20, $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $20; 3630: a0 a0 ce... ..N
    !byte $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce; 3640: 20 ce a0...  N.
    !byte $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce; 3650: a0 a0 cd... ..M
    !byte $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0; 3660: a0 a0 cd... ..M
    !byte $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0; 3670: cd 20 20... M
    !byte $cd, $ce, $a0, $a0, $cd, $20, $20, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd, $20; 3680: cd ce a0... MN.
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3690: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 36a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 36b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 36c0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 36d0: 20 20 20...
    !byte $20, $20, $20, $20, $11, $20, $20, $20, $20, $20, $20, $20, $20, $20, $17, $20; 36e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20,   5, $20, $20, $20, $20, $20, $20, $20; 36f0: 20 20 20...
    !byte $20, $20, $12, $20, $20, $20, $20, $20, $20, $20, $20, $20, $14, $20, $20, $20; 3700: 20 20 12...   .
    !byte $20, $20, $20, $20, $20, $20, $19, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3710: 20 20 20...
    !byte $15, $20, $20, $20, $20, $20, $20, $20, $20, $20,   9, $20, $20, $20, $20, $20; 3720: 15 20 20... .
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3730: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3740: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3750: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3760: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3770: 20 20 20...
    !byte $20, $13,   3, $0f, $12,   5, $3a, $20, $20, $20, $20, $28, $0d,   1, $18, $20; 3780: 20 13 03...  ..
    !byte $32, $30, $30, $29, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3790: 32 30 30... 200
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 37a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 37b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20,   5, $28, $18, $29,   9, $14, $20; 37c0: 20 20 20...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 37d0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 37e0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 37f0: 00 00 00... ...
chr_dat2
    !byte $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0; 3800: cd a0 a0... M..
    !byte $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd; 3810: a0 ce cd... .NM
    !byte $cd, $a0, $a0, $ce, $cd, $a0, $a0, $ce, $a0, $cd, $ce, $a0, $a0, $cd, $ce, $a0; 3820: cd a0 a0... M..
    !byte $a0, $ce, $cd, $a0, $a0, $ce, $cd, $a0, $ce, $a0, $a0, $cd, $ce, $a0, $a0, $cd; 3830: a0 ce cd... .NM
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3840: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3850: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3860: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 3870: 20 20 20...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3880: e8 e8 e8... ...
    !byte $8c, $84, $81, $a0, $a3, $b2, $b2, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3890: 8c 84 81... ...
    !byte $93, $85, $83, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 38a0: 93 85 83... ...
    !byte $81, $84, $83, $a0, $a3, $b2, $b2, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 38b0: 81 84 83... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 38c0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $d5, $db, $c3, $a0, $a0, $a0, $a0; 38d0: a0 a0 a0... ...
    !byte $a0, $ca, $db, $c9, $b2, $84, $a0, $a0, $a0, $c3, $db, $cb, $a0, $a0, $a0, $a0; 38e0: a0 ca db... .J.
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 38f0: e8 e8 e8... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3900: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3910: a0 a0 a0... ...
    !byte $b1, $b0, $b0, $b0, $b0, $b0, $b0, $b1, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3920: b1 b0 b0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3930: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3940: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $d5, $db, $c3, $a0, $a0, $a0, $a0; 3950: a0 a0 a0... ...
    !byte $a0, $ca, $db, $c9, $b8, $b1, $a0, $a0, $a0, $c3, $db, $cb, $a0, $a0, $a0, $a0; 3960: a0 ca db... .J.
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3970: e8 e8 e8... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3980: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $90, $8f, $8b, $85, $a0, $a0, $a0, $a0; 3990: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $b5, $b3, $b2, $b8, $b0, $ac, $b0, $a0; 39a0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 39b0: a0 a0 a0... ...
    !byte $4f, $77, $77, $77, $77, $77, $77, $50, $65, $20, $20, $20, $20, $20, $20, $67; 39c0: 4f 77 77... o..
    !byte $65, $20, $a0, $a0, $a0, $a0, $20, $67, $65, $20, $a0, $a0, $a0, $a0, $20, $67; 39d0: 65 20 a0... . .
    !byte $65, $20, $a0, $a0, $a0, $a0, $20, $67, $65, $20, $a0, $a0, $a0, $a0, $20, $67; 39e0: 65 20 a0... . .
    !byte $65, $20, $20, $20, $20, $20, $20, $67, $4c, $6f, $6f, $6f, $6f, $6f, $6f, $7a; 39f0: 65 20 20... .
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a00: e8 e8 e8... ...
    !byte $b1, $b0, $b0, $b1, $b0, $b0, $b1, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a10: b1 b0 b0... ...
    !byte $a0, $a0, $98, $8f, $92, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a20: a0 a0 98... ...
    !byte $b1, $b0, $b0, $b1, $b0, $b0, $b1, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3a30: b1 b0 b0... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a40: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $d5, $c3, $c9, $a0, $a0, $a0, $a0, $a0, $dd, $af, $dd, $a0; 3a50: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $dd, $af, $dd, $a0, $a0, $a0, $9a, $85, $92, $c3, $cb, $a0; 3a60: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3a70: a0 a0 a0... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a80: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3a90: a0 a0 a0... ...
    !byte $a0, $90, $92, $89, $8e, $94, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3aa0: a0 90 92... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3ab0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $69, $20, $20, $5f, $a0, $a0; 3ac0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $20, $a0, $a0, $a0, $a0, $a0, $69, $20, $e9, $a0, $a0; 3ad0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3ae0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3af0: a0 a0 a0... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3b00: e8 e8 e8... ...
    !byte $a0, $c2, $a0, $ae, $c2, $a0, $a0, $a0, $a0, $eb, $c9, $ee, $c2, $a0, $a0, $a0; 3b10: a0 c2 a0... .B.
    !byte $a0, $ed, $cb, $f1, $ca, $c3, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3b20: a0 ed cb... ..K
    !byte $a0, $a0, $88, $85, $92, $84, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3b30: a0 a0 88... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3b40: e8 e8 e8... ...
    !byte $a0, $c3, $f2, $c3, $a0, $a0, $a0, $a0, $a0, $a0, $dd, $f0, $c3, $f0, $c9, $a0; 3b50: a0 c3 f2... .C.
    !byte $a0, $a0, $c2, $eb, $c3, $c2, $c2, $a0, $a0, $a0, $c2, $ed, $c3, $ed, $cb, $a0; 3b60: a0 a0 c2... ..B
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3b70: a0 a0 a0... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3b80: e8 e8 e8... ...
    !byte $a0, $c2, $a0, $a0, $a0, $c2, $a0, $a0, $a0, $eb, $c9, $d5, $c9, $eb, $c9, $a0; 3b90: a0 c2 a0... .B.
    !byte $a0, $ed, $cb, $ca, $cb, $ed, $cb, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3ba0: a0 ed cb... ..K
    !byte $a0, $99, $81, $8e, $8e, $85, $93, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3bb0: a0 99 81... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3bc0: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $d5, $c0, $ae, $f0, $c9, $a0, $a0; 3bd0: a0 a0 a0... ...
    !byte $a0, $ca, $c9, $c2, $c2, $c2, $a0, $a0, $a0, $c0, $cb, $f1, $ed, $cb, $a0, $a0; 3be0: a0 ca c9... .JI
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3bf0: a0 a0 a0... ...
    !byte $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0; 3c00: e8 e8 e8... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $90, $8f, $8b, $85, $a0, $a0, $a0, $a0; 3c10: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $b1, $b0, $b2, $b4, $ac, $b1, $a0, $a0; 3c20: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $e8, $e8, $e8, $e8, $e8, $e8, $e8, $e8; 3c30: a0 a0 a0... ...
    !byte $4f, $77, $77, $77, $77, $77, $77, $50, $74,   1, $20, $20, $20, $20, $20, $67; 3c40: 4f 77 77... o..
    !byte $74, $20, $20, $20, $20, $20, $20, $67, $74, $20, $20, $20, $20, $20, $20, $67; 3c50: 74 20 20... .
    !byte $74, $20, $20, $20, $20, $20, $20, $67, $74, $20, $20, $20, $20, $20, $20, $67; 3c60: 74 20 20... .
    !byte $74, $20, $20, $20, $20, $20, $20, $67, $4c, $6f, $6f, $6f, $6f, $6f, $6f, $7a; 3c70: 74 20 20... .
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3c80: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3c90: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ca0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3cb0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3cc0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3cd0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ce0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3cf0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d00: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d10: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d20: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d30: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d40: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d50: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d60: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d70: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d80: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3d90: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3da0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3db0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3dc0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3dd0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3de0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3df0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e00: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e10: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e20: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e30: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e40: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e50: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e60: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e70: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e80: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3e90: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ea0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3eb0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ec0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ed0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ee0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ef0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f00: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f10: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f20: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f30: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f40: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f50: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f60: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f70: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f80: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3f90: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3fa0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3fb0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3fc0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3fd0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3fe0: 00 00 00... ...
    !byte   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0; 3ff0: 00 00 00... ...
chr_dat3
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4000: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4010: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4020: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4030: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4040: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4050: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4060: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4070: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4080: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4090: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 40a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 40b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 40c0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 40d0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 40e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $a0, $a0, $a0, $20, $20, $20, $20, $20; 40f0: 20 20 20...
    !byte $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $a0, $a0, $a0, $a0, $a0, $20; 4100: 20 20 20...
    !byte $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $a0, $a0; 4110: 20 20 20...
    !byte $a0, $a0, $a0, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20; 4120: a0 a0 a0... ...
    !byte $20, $20, $20, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4130: 20 20 20...
    !byte $20, $20, $20, $a0, $a0, $a0, $20, $66, $a0, $a0, $a0, $20, $20, $a0, $a0, $a0; 4140: 20 20 20...
    !byte $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $66, $66, $a0, $a0, $a0, $20, $20; 4150: 20 20 20...
    !byte $20, $a0, $a0, $a0, $66, $66, $66, $66, $66, $a0, $a0, $a0, $20, $66, $66, $a0; 4160: 20 a0 a0...  ..
    !byte $a0, $a0, $20, $20, $66, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20, $a0, $a0; 4170: a0 a0 20... ..
    !byte $a0, $20, $66, $a0, $a0, $a0, $20, $20, $a0, $a0, $a0, $20, $20, $20, $20, $20; 4180: a0 20 66... . .
    !byte $20, $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $66, $20; 4190: 20 20 66...   .
    !byte $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $a0, $a0, $a0, $20, $20, $20; 41a0: 20 20 20...
    !byte $a0, $a0, $a0, $20, $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $66, $a0; 41b0: a0 a0 a0... ...
    !byte $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $66, $66, $66; 41c0: a0 a0 20... ..
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20, $20, $20, $20; 41d0: a0 a0 a0... ...
    !byte $20, $20, $20, $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20; 41e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $66; 41f0: 20 20 20...
    !byte $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $66, $a0; 4200: a0 a0 a0... ...
    !byte $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $66; 4210: a0 a0 20... ..
    !byte $66, $66, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20, $20, $20, $20, $20, $20; 4220: 66 66 a0... ...
    !byte $20, $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20; 4230: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $20, $20, $20, $66; 4240: 20 20 20...
    !byte $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $66, $a0; 4250: a0 a0 a0... ...
    !byte $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $20; 4260: a0 a0 20... ..
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $20; 4270: a0 a0 a0... ...
    !byte $20, $20, $20, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0; 4280: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $66; 4290: 20 20 20...
    !byte $66, $a0, $a0, $a0, $20, $20, $20, $20, $20, $a0, $a0, $a0, $20, $20, $66, $a0; 42a0: 66 a0 a0... ...
    !byte $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20, $a0, $a0; 42b0: a0 a0 20... ..
    !byte $a0, $66, $66, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20; 42c0: a0 66 66... ...
    !byte $20, $20, $66, $66, $66, $20, $20, $66, $a0, $a0, $a0, $20, $66, $66, $66, $20; 42d0: 20 20 66...   .
    !byte $20, $20, $20, $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20; 42e0: 20 20 20...
    !byte $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20, $66, $66; 42f0: 66 66 66... ...
    !byte $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20, $66, $66, $66; 4300: a0 a0 a0... ...
    !byte $20, $20, $66, $a0, $a0, $a0, $20, $66, $66, $66, $20, $20, $20, $20, $20, $20; 4310: 20 20 66...   .
    !byte $20, $20, $20, $20, $20, $20, $20, $66, $66, $66, $20, $20, $20, $20, $20, $20; 4320: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $66, $66, $66, $66, $66, $20, $20, $20, $20, $20; 4330: 20 20 20...
    !byte $20, $20, $66, $66, $66, $66, $66, $66, $66, $20, $20, $20, $20, $20, $20, $66; 4340: 20 20 66...   .
    !byte $66, $66, $66, $66, $66, $66, $66, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4350: 66 66 66... ...
    !byte $20, $20, $66, $66, $66, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4360: 20 20 66...   .
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4370: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4380: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4390: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43c0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43d0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 43f0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4400: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4410: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4420: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4430: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4440: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4450: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $a0, $a0, $a0, $20, $20, $20, $20, $20; 4460: 20 20 20...
    !byte $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $a0, $a0, $a0, $20; 4470: 20 20 20...
    !byte $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $a0, $a0, $a0, $a0, $a0, $20, $a0, $a0; 4480: 20 20 a0...   .
    !byte $a0, $a0, $a0, $a0, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20; 4490: a0 a0 a0... ...
    !byte $20, $20, $20, $20, $20, $a0, $a0, $a0, $20, $20, $20, $20, $20, $20, $20, $20; 44a0: 20 20 20...
    !byte $20, $20, $20, $a0, $a0, $a0, $20, $66, $a0, $a0, $a0, $20, $20, $a0, $a0, $a0; 44b0: 20 20 20...
    !byte $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20; 44c0: 20 20 20...
    !byte $20, $66, $66, $a0, $a0, $a0, $20, $66, $66, $a0, $a0, $a0, $20, $66, $66, $a0; 44d0: 20 66 66...  ..
    !byte $a0, $a0, $a0, $a0, $a0, $20, $66, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20; 44e0: a0 a0 a0... ...
    !byte $a0, $a0, $a0, $20, $66, $a0, $a0, $a0, $20, $20, $a0, $a0, $a0, $20, $20, $20; 44f0: a0 a0 a0... ...
    !byte $20, $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $66, $20; 4500: 20 20 66...   .
    !byte $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20; 4510: 20 20 20...
    !byte $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0; 4520: 20 20 66...   .
    !byte $a0, $a0, $66, $a0, $a0, $a0, $20, $66, $a0, $a0, $a0, $20, $20, $20, $20, $66; 4530: a0 a0 66... ...
    !byte $66, $66, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20, $20; 4540: 66 66 a0... ...
    !byte $20, $20, $20, $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20; 4550: 20 20 20...
    !byte $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20; 4560: 20 20 20...
    !byte $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0; 4570: 20 20 66...   .
    !byte $a0, $a0, $66, $66, $a0, $a0, $a0, $66, $a0, $a0, $a0, $20, $20, $20, $20, $20; 4580: a0 a0 66... ...
    !byte $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $66, $20, $20, $20, $20, $20, $20; 4590: 20 66 66...  ..
    !byte $20, $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20; 45a0: 20 20 20...
    !byte $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $20, $a0, $a0, $a0, $a0, $a0; 45b0: 20 20 20...
    !byte $20, $20, $a0, $a0, $a0, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0; 45c0: 20 20 a0...   .
    !byte $a0, $a0, $20, $66, $66, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20; 45d0: a0 a0 20... ..
    !byte $20, $20, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20; 45e0: 20 20 a0...   .
    !byte $20, $20, $20, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0; 45f0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $66, $66, $66, $a0, $a0, $a0, $a0, $a0, $66, $a0, $a0; 4600: 20 20 20...
    !byte $a0, $a0, $a0, $66, $20, $20, $20, $20, $66, $a0, $a0, $a0, $20, $20, $66, $a0; 4610: a0 a0 a0... ...
    !byte $a0, $a0, $20, $20, $66, $66, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $20, $20; 4620: a0 a0 20... ..
    !byte $a0, $a0, $a0, $66, $66, $a0, $a0, $a0, $66, $66, $a0, $a0, $a0, $20, $20, $20; 4630: a0 a0 a0... ...
    !byte $20, $20, $66, $66, $66, $20, $20, $66, $a0, $a0, $a0, $20, $66, $66, $66, $20; 4640: 20 20 66...   .
    !byte $20, $20, $20, $20, $20, $20, $20, $66, $66, $a0, $a0, $a0, $20, $66, $66, $a0; 4650: 20 20 20...
    !byte $a0, $a0, $20, $20, $20, $20, $20, $20, $a0, $a0, $a0, $a0, $a0, $20, $a0, $a0; 4660: a0 a0 20... ..
    !byte $a0, $a0, $a0, $20, $20, $66, $66, $a0, $a0, $a0, $a0, $a0, $20, $20, $20, $66; 4670: a0 a0 a0... ...
    !byte $66, $66, $20, $20, $66, $a0, $a0, $a0, $20, $66, $66, $66, $20, $20, $20, $20; 4680: 66 66 20... ..
    !byte $20, $20, $20, $20, $20, $20, $20, $66, $66, $66, $20, $20, $20, $20, $20, $20; 4690: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $66, $66, $66, $20, $20, $20, $66, $66; 46a0: 20 20 20...
    !byte $66, $20, $20, $20, $20, $20, $20, $66, $66, $66, $66, $66, $20, $66, $66, $66; 46b0: 66 20 20... .
    !byte $66, $66, $20, $20, $20, $20, $66, $66, $66, $66, $66, $20, $20, $20, $20, $20; 46c0: 66 66 20... ..
    !byte $20, $20, $20, $20, $66, $66, $66, $20, $20, $20, $20, $20, $20, $20, $20, $20; 46d0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 46e0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 46f0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4700: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4710: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4720: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4730: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4740: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4750: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4760: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4770: 20 20 20...
    !byte $20, $13,   3, $0f, $12,   5, $3a, $20, $20, $20, $20, $28, $0d,   1, $18, $20; 4780: 20 13 03...  ..
    !byte $32, $30, $30, $29, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 4790: 32 30 30... 200
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 47a0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20, $20; 47b0: 20 20 20...
    !byte $20, $20, $20, $20, $20, $20, $20, $20, $20,   5, $28, $18, $29,   9, $14, $20; 47c0: 20 20 20...
pydis_end

!if (basic_end) != $1c0b {
    !error "Assertion failed: basic_end == $1c0b"
}
!if (show_1) != $216f {
    !error "Assertion failed: show_1 == $216f"
}
!if (show_2) != $21aa {
    !error "Assertion failed: show_2 == $21aa"
}
!if (show_3) != $21e5 {
    !error "Assertion failed: show_3 == $21e5"
}
!if (show_4) != $2220 {
    !error "Assertion failed: show_4 == $2220"
}
!if (show_5) != $225b {
    !error "Assertion failed: show_5 == $225b"
}
!if (show_6) != $2296 {
    !error "Assertion failed: show_6 == $2296"
}
!if (show_7) != $22d1 {
    !error "Assertion failed: show_7 == $22d1"
}
!if (show_8) != $230c {
    !error "Assertion failed: show_8 == $230c"
}
!if (show_E) != $23bd {
    !error "Assertion failed: show_E == $23bd"
}
!if (show_I) != $24e4 {
    !error "Assertion failed: show_I == $24e4"
}
!if (show_Q) != $2347 {
    !error "Assertion failed: show_Q == $2347"
}
!if (show_R) != $23f8 {
    !error "Assertion failed: show_R == $23f8"
}
!if (show_T) != $2433 {
    !error "Assertion failed: show_T == $2433"
}
!if (show_U) != $24a9 {
    !error "Assertion failed: show_U == $24a9"
}
!if (show_W) != $2382 {
    !error "Assertion failed: show_W == $2382"
}
!if (show_Y) != $246e {
    !error "Assertion failed: show_Y == $246e"
}

; Label references by decreasing frequency:
;     vdcout:                      125
;     dst_high:                     76
;     dst_low:                      76
;     vdcin:                        34
;     src_high:                     24
;     src_low:                      24
;     match:                        19
;     l00fa:                        18
;     l00fb:                        17
;     display_card:                 16
;     l00fc:                        14
;     l00fd:                        13
;     score:                         7
;     cia1_tod_seconds:              6
;     cia1_tod_tenths:               6
;     param:                         6
;     match_cnt:                     4
;     reset_card:                    4
;     dst_high_crd1:                 3
;     dst_high_crd2:                 3
;     dst_low_crd1:                  3
;     dst_low_crd2:                  3
;     sid_volume_filter_mode:        3
;     used:                          3
;     value_2:                       3
;     array:                         2
;     c2bc5:                         2
;     fill_loop:                     2
;     freqs:                         2
;     jsr_card_reset:                2
;     jump_addr:                     2
;     l2521:                         2
;     l2522:                         2
;     l2523:                         2
;     l2524:                         2
;     l2525:                         2
;     l2526:                         2
;     l2527:                         2
;     l2528:                         2
;     l2529:                         2
;     l252a:                         2
;     l252b:                         2
;     l252c:                         2
;     l252d:                         2
;     l252e:                         2
;     l252f:                         2
;     l2530:                         2
;     l2531:                         2
;     l2532:                         2
;     l2533:                         2
;     l2534:                         2
;     l2535:                         2
;     l2536:                         2
;     l2537:                         2
;     l2538:                         2
;     l2539:                         2
;     l253a:                         2
;     l253b:                         2
;     l253c:                         2
;     l253d:                         2
;     l253e:                         2
;     l2542:                         2
;     l2543:                         2
;     l2544:                         2
;     lc000:                         2
;     loop_ch:                       2
;     loop_ch2:                      2
;     loop_ch3:                      2
;     mmu_configuration:             2
;     sid_voice1_control:            2
;     sid_voice3_control:            2
;     special_card_face_array:       2
;     value_1:                       2
;     vdc_screen_base:               2
;     c2677:                         1
;     c2817:                         1
;     c288c:                         1
;     c28b2:                         1
;     c28d8:                         1
;     c28fe:                         1
;     c2924:                         1
;     c294a:                         1
;     c2970:                         1
;     c2996:                         1
;     c29bc:                         1
;     c29e2:                         1
;     c2a08:                         1
;     c2a2e:                         1
;     c2a54:                         1
;     c2a7a:                         1
;     c2aa0:                         1
;     c2ac6:                         1
;     c2b51:                         1
;     card_face_array:               1
;     card_match:                    1
;     card_pos_array:                1
;     card_reset:                    1
;     check_no_cards:                1
;     clear_used:                    1
;     copy:                          1
;     decout:                        1
;     decout_hund_done:              1
;     decout_hund_loop:              1
;     decout_tens_done:              1
;     decout_tens_loop:              1
;     exit:                          1
;     fill_unique_array:             1
;     found_key:                     1
;     getin:                         1
;     handle_input:                  1
;     handler_table:                 1
;     inner_loop:                    1
;     key_table:                     1
;     l2013:                         1
;     l2150:                         1
;     l2520:                         1
;     l253f:                         1
;     l2540:                         1
;     l2616:                         1
;     l2617:                         1
;     l2619:                         1
;     l261a:                         1
;     l261b:                         1
;     l261d:                         1
;     l261e:                         1
;     l261f:                         1
;     l2621:                         1
;     l2622:                         1
;     l2623:                         1
;     l2625:                         1
;     l2626:                         1
;     l2627:                         1
;     l2629:                         1
;     l262a:                         1
;     l262b:                         1
;     l262d:                         1
;     l262e:                         1
;     l262f:                         1
;     l2631:                         1
;     l2632:                         1
;     l2633:                         1
;     l2635:                         1
;     l2636:                         1
;     l2637:                         1
;     l2639:                         1
;     l263a:                         1
;     l263b:                         1
;     l263d:                         1
;     l263e:                         1
;     l263f:                         1
;     l2641:                         1
;     l2642:                         1
;     l2643:                         1
;     l2645:                         1
;     l2646:                         1
;     l2647:                         1
;     l2649:                         1
;     l264a:                         1
;     l264b:                         1
;     l264d:                         1
;     l264e:                         1
;     l264f:                         1
;     l2651:                         1
;     l2652:                         1
;     l2653:                         1
;     loop_c2737:                    1
;     loop_c273e:                    1
;     loop_c27c2:                    1
;     loop_c27c9:                    1
;     loop_c2ae0:                    1
;     loop_c2afd:                    1
;     loop_c2c5f:                    1
;     loop_c2c66:                    1
;     main_loop:                     1
;     no_key:                        1
;     out_loop:                      1
;     play_loop:                     1
;     play_match_snd:                1
;     quit_game:                     1
;     return_1:                      1
;     return_10:                     1
;     return_11:                     1
;     return_12:                     1
;     return_13:                     1
;     return_14:                     1
;     return_15:                     1
;     return_16:                     1
;     return_2:                      1
;     return_3:                      1
;     return_4:                      1
;     return_5:                      1
;     return_6:                      1
;     return_7:                      1
;     return_8:                      1
;     return_9:                      1
;     return_from_card_match:        1
;     return_from_store_cord_2:      1
;     search_loop:                   1
;     set_score_to_zero:             1
;     show_win:                      1
;     sid_voice1_attack_decay:       1
;     sid_voice1_frequency_high:     1
;     sid_voice1_frequency_low:      1
;     sid_voice1_pulse_width_high:   1
;     sid_voice1_pulse_width_low:    1
;     sid_voice1_sustain_release:    1
;     sid_voice3_frequency_high:     1
;     sid_voice3_frequency_low:      1
;     sid_voice3_oscillator:         1
;     store_cord_1:                  1
;     store_cord_2:                  1

; Automatically generated labels:
;     c2677
;     c2817
;     c288c
;     c28b2
;     c28d8
;     c28fe
;     c2924
;     c294a
;     c2970
;     c2996
;     c29bc
;     c29e2
;     c2a08
;     c2a2e
;     c2a54
;     c2a7a
;     c2aa0
;     c2ac6
;     c2b51
;     c2bc5
;     l00fa
;     l00fb
;     l00fc
;     l00fd
;     l2013
;     l2150
;     l2520
;     l2521
;     l2522
;     l2523
;     l2524
;     l2525
;     l2526
;     l2527
;     l2528
;     l2529
;     l252a
;     l252b
;     l252c
;     l252d
;     l252e
;     l252f
;     l2530
;     l2531
;     l2532
;     l2533
;     l2534
;     l2535
;     l2536
;     l2537
;     l2538
;     l2539
;     l253a
;     l253b
;     l253c
;     l253d
;     l253e
;     l253f
;     l2540
;     l2542
;     l2543
;     l2544
;     l2616
;     l2617
;     l2619
;     l261a
;     l261b
;     l261d
;     l261e
;     l261f
;     l2621
;     l2622
;     l2623
;     l2625
;     l2626
;     l2627
;     l2629
;     l262a
;     l262b
;     l262d
;     l262e
;     l262f
;     l2631
;     l2632
;     l2633
;     l2635
;     l2636
;     l2637
;     l2639
;     l263a
;     l263b
;     l263d
;     l263e
;     l263f
;     l2641
;     l2642
;     l2643
;     l2645
;     l2646
;     l2647
;     l2649
;     l264a
;     l264b
;     l264d
;     l264e
;     l264f
;     l2651
;     l2652
;     l2653
;     lc000
;     loop_c2737
;     loop_c273e
;     loop_c27c2
;     loop_c27c9
;     loop_c2ae0
;     loop_c2afd
;     loop_c2c5f
;     loop_c2c66
;     return_1
;     return_10
;     return_11
;     return_12
;     return_13
;     return_14
;     return_15
;     return_16
;     return_2
;     return_3
;     return_4
;     return_5
;     return_6
;     return_7
;     return_8
;     return_9

; Stats:
;
;     Total size (Code + Data) = 11215 bytes
;     Code                     = 2895 bytes (26%)
;     Data                     = 8320 bytes (74%)
;
;     Number of instructions   = 1198
;     Number of data bytes     = 8260 bytes
;     Number of data words     = 40 bytes
;     Number of string bytes   = 20 bytes
;     Number of strings        = 2

