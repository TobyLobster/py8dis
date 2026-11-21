; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .org $0e00

pydis_start:
    .byte l0e06 - l0e01                                               ; 0e00: 05          .
l0e01:
    .byte "hello"                                                     ; 0e01: 68 65 6c... hel
l0e06:
    .byte pydis_end - l0e07                                           ; 0e06: 05          .
l0e07:
    .byte "wo", $0d, "ld"                                             ; 0e07: 77 6f 0d... wo.
pydis_end:

.assert (l0e06 - l0e01) = $05, error, "Assertion failed: l0e06 - l0e01 = $05"
.assert (pydis_end - l0e07) = $05, error, "Assertion failed: pydis_end - l0e07 = $05"

; Stats:
;
;     Total size (Code + Data) = 12 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 12 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 2 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 10 bytes
;     Number of strings        = 2

