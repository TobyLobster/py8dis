; Assemble with ca65 and its linker (from cc65), to a plain binary:
;     cl65 -t none -C ca65.cfg -o program.bin this_file.asm
; where ca65.cfg (as in py8dis's examples/ca65.cfg) holds:
;     MEMORY { MAIN: start = $0000, size = $10000, file = %O; }
;     SEGMENTS { CODE: load = MAIN, type = rw; }
; ('-t none': cl65's default target is the C64, whose character map would change
; the strings.)

    .org $0e00

pydis_start:
    .byte "Hello"                                                     ; 0e00: 48 65 6c... Hel
    .incbin "orig/include_binary_data.bin"
    .byte " world"                                                    ; 0e0d: 20 77 6f...  wo
pydis_end:


; Stats:
;
;     Total size (Code + Data) = 19 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 19 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 8 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 11 bytes
;     Number of strings        = 2

