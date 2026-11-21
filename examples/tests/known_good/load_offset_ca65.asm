; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations
chrout  = $ffd2

    .org $0801

pydis_start:
    .byte $0b, 8, $0a, 0, $9e                                         ; 0801: 0b 08 0a... ...
    .byte "2061"                                                      ; 0806: 32 30 36... 206
    .byte 0, 0, 0                                                     ; 080a: 00 00 00    ...

start:
    ldx #0                                                            ; 080d: a2 00       ..
; $080f referenced 1 time by $0818
loop_c080f:
    lda l081b,x                                                       ; 080f: bd 1b 08    ...
    beq return_1                                                      ; 0812: f0 06       ..
    jsr chrout                                                        ; 0814: 20 d2 ff     ..
    inx                                                               ; 0817: e8          .
    bne loop_c080f                                                    ; 0818: d0 f5       ..
; $081a referenced 1 time by $0812
return_1:
    rts                                                               ; 081a: 60          `

; $081b referenced 1 time by $080f
l081b:
    .byte "HELLO"                                                     ; 081b: 48 45 4c... HEL
    .byte $0d, 0                                                      ; 0820: 0d 00       ..
pydis_end:


; Label references by decreasing frequency:
;     chrout:       1
;     l081b:        1
;     loop_c080f:   1
;     return_1:     1

; Automatically generated labels:
;     l081b
;     loop_c080f
;     return_1

; Stats:
;
;     Total size (Code + Data) = 33 bytes
;     Code                     = 14 bytes (42%)
;     Data                     = 19 bytes (58%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 10 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 9 bytes
;     Number of strings        = 2

