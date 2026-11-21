; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

    org $ffe0

pydis_start
    dfb $a2, $80                                                      ; ffe0: a2 80       ..
    asc '0<L'                                                         ; ffe2: 30 3c 4c    0<L
    dfb $fd, $ff                                                      ; ffe5: fd ff       ..
    asc 'THE TOP OF MEMORY'                                           ; ffe7: 54 48 45... THE
    dfb 0, 0, 0, 0, 0                                                 ; fff8: 00 00 00... ...
    asc ',,A'                                                         ; fffd: 2c 2c 41    ,,A
pydis_end


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
