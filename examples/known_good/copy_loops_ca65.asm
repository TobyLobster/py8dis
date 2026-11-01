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

; Other
l3000   = $3000
l3100   = $3100
l3282   = $3282
l3382   = $3382
table3  = $33fd
l3502   = $3502
l3601   = $3601
l3701   = $3701
l3800   = $3800
l3900   = $3900
l3a80   = $3a80
l3b80   = $3b80
l3c02   = $3c02
table7  = $3cf0
l3e00   = $3e00
l3f00   = $3f00
l3f80   = $3f80

    .org $2000

pydis_start:
start:
    ; Copy 256 bytes of memory from l3000 to l3100
    ldx #0                                                            ; 2000: a2 00       ..
; $2002 referenced 1 time by $2009
loop_c2002:
    lda l3000,x                                                       ; 2002: bd 00 30    ..0
    sta l3100,x                                                       ; 2005: 9d 00 31    ..1
    dex                                                               ; 2008: ca          .
    bne loop_c2002                                                    ; 2009: d0 f7       ..
    ; Copy 1 byte of memory from l3282 to l3382
    ldy #$82                                                          ; 200b: a0 82       ..
; $200d referenced 1 time by $2014
loop_c200d:
    lda l3282 - 130,y                                                 ; 200d: b9 00 32    ..2
    sta l3382 - 130,y                                                 ; 2010: 99 00 33    ..3
    dey                                                               ; 2013: 88          .
    bpl loop_c200d                                                    ; 2014: 10 f7       ..
    ; Copy 8 bytes of memory from (table3+3) + 2 to l3502
    ldy #9                                                            ; 2016: a0 09       ..
; $2018 referenced 1 time by $2021
loop_c2018:
    lda table3+3,y                                                    ; 2018: b9 00 34    ..4
    sta l3502 - 2,y                                                   ; 201b: 99 00 35    ..5
    dey                                                               ; 201e: 88          .
    cpy #2                                                            ; 201f: c0 02       ..
    bcs loop_c2018                                                    ; 2021: b0 f5       ..
    ; Copy 1 byte of memory from l3601 to l3701
    ldx #1                                                            ; 2023: a2 01       ..
; $2025 referenced 1 time by $202e
loop_c2025:
    lda l3601 - 1,x                                                   ; 2025: bd 00 36    ..6
    sta l3701 - 1,x                                                   ; 2028: 9d 00 37    ..7
    dex                                                               ; 202b: ca          .
    cpx #4                                                            ; 202c: e0 04       ..
    bcs loop_c2025                                                    ; 202e: b0 f5       ..
    ldx #$f0                                                          ; 2030: a2 f0       ..
; $2032 referenced 1 time by $203b
loop_c2032:
    lda l3800,x                                                       ; 2032: bd 00 38    ..8
    sta l3900,x                                                       ; 2035: 9d 00 39    ..9
    inx                                                               ; 2038: e8          .
    cpx #$10                                                          ; 2039: e0 10       ..
    bne loop_c2032                                                    ; 203b: d0 f5       ..
    ; Copy 128 bytes of memory from l3a80 to l3b80
    ldy #$80                                                          ; 203d: a0 80       ..
; $203f referenced 1 time by $2048
loop_c203f:
    lda l3a80 - 128,y                                                 ; 203f: b9 00 3a    ..:
    sta l3b80 - 128,y                                                 ; 2042: 99 00 3b    ..;
    iny                                                               ; 2045: c8          .
    cpy #0                                                            ; 2046: c0 00       ..
    bne loop_c203f                                                    ; 2048: d0 f5       ..
    ; Copy 6 bytes of memory from l3c02 to (table7+16) + 2
    ldx #2                                                            ; 204a: a2 02       ..
; $204c referenced 1 time by $2055
loop_c204c:
    lda l3c02 - 2,x                                                   ; 204c: bd 00 3c    ..<
    sta table7+16,x                                                   ; 204f: 9d 00 3d    ..=
    inx                                                               ; 2052: e8          .
    cpx #8                                                            ; 2053: e0 08       ..
    bcc loop_c204c                                                    ; 2055: 90 f5       ..
    ; Clear 256 bytes of memory at l3e00+Y
    lda #0                                                            ; 2057: a9 00       ..
    ldy l3f00                                                         ; 2059: ac 00 3f    ..?
    ldx #0                                                            ; 205c: a2 00       ..
; $205e referenced 1 time by $2063
loop_c205e:
    sta l3e00,y                                                       ; 205e: 99 00 3e    ..>
    iny                                                               ; 2061: c8          .
    dex                                                               ; 2062: ca          .
    bne loop_c205e                                                    ; 2063: d0 f9       ..
    ; Set 4 bytes of memory at l3f80+Y to 255
    lda #$ff                                                          ; 2065: a9 ff       ..
    ldy l0070                                                         ; 2067: a4 70       .p
    ldx #4                                                            ; 2069: a2 04       ..
; $206b referenced 1 time by $2070
loop_c206b:
    sta l3f80,y                                                       ; 206b: 99 80 3f    ..?
    iny                                                               ; 206e: c8          .
    dex                                                               ; 206f: ca          .
    bne loop_c206b                                                    ; 2070: d0 f9       ..
    rts                                                               ; 2072: 60          `

pydis_end:

.assert (l3282 - 130) = $3200, error, "Assertion failed: l3282 - 130 = $3200"
.assert (l3382 - 130) = $3300, error, "Assertion failed: l3382 - 130 = $3300"
.assert (l3502 - 2) = $3500, error, "Assertion failed: l3502 - 2 = $3500"
.assert (l3601 - 1) = $3600, error, "Assertion failed: l3601 - 1 = $3600"
.assert (l3701 - 1) = $3700, error, "Assertion failed: l3701 - 1 = $3700"
.assert (l3a80 - 128) = $3a00, error, "Assertion failed: l3a80 - 128 = $3a00"
.assert (l3b80 - 128) = $3b00, error, "Assertion failed: l3b80 - 128 = $3b00"
.assert (l3c02 - 2) = $3c00, error, "Assertion failed: l3c02 - 2 = $3c00"
.assert (table3+3) = $3400, error, "Assertion failed: table3+3 = $3400"
.assert (table7+16) = $3d00, error, "Assertion failed: table7+16 = $3d00"

; Label references by decreasing frequency:
;     l0070:        1
;     l3000:        1
;     l3100:        1
;     l3800:        1
;     l3900:        1
;     l3e00:        1
;     l3f00:        1
;     l3f80:        1
;     loop_c2002:   1
;     loop_c200d:   1
;     loop_c2018:   1
;     loop_c2025:   1
;     loop_c2032:   1
;     loop_c203f:   1
;     loop_c204c:   1
;     loop_c205e:   1
;     loop_c206b:   1

; Automatically generated labels:
;     l0070
;     l3000
;     l3100
;     l3282
;     l3382
;     l3502
;     l3601
;     l3701
;     l3800
;     l3900
;     l3a80
;     l3b80
;     l3c02
;     l3e00
;     l3f00
;     l3f80
;     loop_c2002
;     loop_c200d
;     loop_c2018
;     loop_c2025
;     loop_c2032
;     loop_c203f
;     loop_c204c
;     loop_c205e
;     loop_c206b

; Stats:
;
;     Total size (Code + Data) = 115 bytes
;     Code                     = 115 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 55
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

