; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations
lfded   = $fded

; The DOS 3.3 file's header
    .org $5ffc
    .word $6000 ; Load address
    .word $0015 ; Length

    .org $6000

pydis_start:
start:
    ldx #0                                                            ; 6000: a2 00       ..
; $6002 referenced 1 time by $600b
loop_c6002:
    lda l600e,x                                                       ; 6002: bd 0e 60    ..`
    beq return_1                                                      ; 6005: f0 06       ..
    jsr lfded                                                         ; 6007: 20 ed fd     ..
    inx                                                               ; 600a: e8          .
    bne loop_c6002                                                    ; 600b: d0 f5       ..
; $600d referenced 1 time by $6005
return_1:
    rts                                                               ; 600d: 60          `

; $600e referenced 1 time by $6002
l600e:
    .byte $c8, $c5, $cc, $cc, $cf, $8d, 0                             ; 600e: c8 c5 cc... ...
pydis_end:


; Label references by decreasing frequency:
;     l600e:        1
;     lfded:        1
;     loop_c6002:   1
;     return_1:     1

; Automatically generated labels:
;     l600e
;     lfded
;     loop_c6002
;     return_1

; Stats:
;
;     Total size (Code + Data) = 21 bytes
;     Code                     = 14 bytes (67%)
;     Data                     = 7 bytes (33%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 7 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

