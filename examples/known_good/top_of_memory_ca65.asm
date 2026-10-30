; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

; Memory locations
l412c   = $412c

    .org $ffe0

pydis_start:
start:
    ldx #$80                                                          ; ffe0: a2 80       ..
    bmi *+62                                                          ; ffe2: 30 3c       0< ; ALWAYS branch

    jmp cfffd                                                         ; ffe4: 4c fd ff    L..

    .byte "THE TOP OF MEMORY"                                         ; ffe7: 54 48 45... THE
    .byte 0, 0, 0, 0, 0                                               ; fff8: 00 00 00... ...

; $fffd referenced 1 time by $ffe4
cfffd:
    bit l412c                                                         ; fffd: 2c 2c 41    ,,A
pydis_end:


; Label references by decreasing frequency:
;     cfffd:   1
;     l412c:   1

; Automatically generated labels:
;     cfffd
;     l412c

; Stats:
;
;     Total size (Code + Data) = 32 bytes
;     Code                     = 10 bytes (31%)
;     Data                     = 22 bytes (69%)
;
;     Number of instructions   = 4
;     Number of data bytes     = 5 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 17 bytes
;     Number of strings        = 1

