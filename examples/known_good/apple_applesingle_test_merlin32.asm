; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations
lfded   equ $fded

; The AppleSingle file's header
    org $07b8
    dfb 0, $05, $16, 0 ; AppleSingle's magic number
    dfb 0, $02, 0, 0 ; Version 2
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ; Filler
    dfb 0, $03 ; 3 entries
    dfb 0, 0, 0, $03, 0, 0, 0, $3e, 0, 0, 0, $05 ; Entry 1: real name, at offset 62, 5 bytes
    dfb 0, 0, 0, $0b, 0, 0, 0, $43, 0, 0, 0, $08 ; Entry 2: ProDOS file info, at offset 67, 8 bytes
    dfb 0, 0, 0, $01, 0, 0, 0, $4b, 0, 0, 0, $15 ; Entry 3: data fork, at offset 75, 21 bytes
    dfb $48, $45, $4c, $4c, $4f ; Real name: "HELLO"
    dfb 0, $c3 ; Access: $c3
    dfb 0, $06 ; File type: $06 (BIN)
    dfb 0, 0, $08, $03 ; Aux type: $0803

    org $0803

pydis_start
start
    ldx #0                                                            ; 0803: a2 00       ..
; $0805 referenced 1 time by $080e
loop_c0805
    lda l0811,x                                                       ; 0805: bd 11 08    ...
    beq return_1                                                      ; 0808: f0 06       ..
    jsr lfded                                                         ; 080a: 20 ed fd     ..
    inx                                                               ; 080d: e8          .
    bne loop_c0805                                                    ; 080e: d0 f5       ..
; $0810 referenced 1 time by $0808
return_1
    rts                                                               ; 0810: 60          `

; $0811 referenced 1 time by $0805
l0811
    dfb $c8, $c5, $cc, $cc, $cf, $8d, 0                               ; 0811: c8 c5 cc... ...
pydis_end


; Label references by decreasing frequency:
;     l0811:        1
;     lfded:        1
;     loop_c0805:   1
;     return_1:     1

; Automatically generated labels:
;     l0811
;     lfded
;     loop_c0805
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
