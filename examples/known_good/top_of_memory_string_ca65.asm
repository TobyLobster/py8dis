; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .org $ffe0

pydis_start:
    .byte $a2, $80                                                    ; ffe0: a2 80       ..
    .byte "0<L"                                                       ; ffe2: 30 3c 4c    0<L
    .byte $fd, $ff                                                    ; ffe5: fd ff       ..
    .byte "THE TOP OF MEMORY"                                         ; ffe7: 54 48 45... THE
    .byte 0, 0, 0, 0, 0                                               ; fff8: 00 00 00... ...
    .byte ",,A"                                                       ; fffd: 2c 2c 41    ,,A
pydis_end:


; Stats:
;
;     Total size (Code + Data) = 32 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 32 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 9 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 23 bytes
;     Number of strings        = 3

