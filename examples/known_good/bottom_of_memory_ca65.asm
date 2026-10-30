; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .org $0000

pydis_start:
start:
    nop                                                               ; 0000: ea          .
    nop                                                               ; 0001: ea          .
    bmi *-16                                                          ; 0002: 30 ee       0.
    rts                                                               ; 0004: 60          `

pydis_end:


; Label references by decreasing frequency:

; Stats:
;
;     Total size (Code + Data) = 5 bytes
;     Code                     = 5 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 4
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

