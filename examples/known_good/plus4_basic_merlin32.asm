; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; The PRG file's header: the address to load it at
    org $0fff
    da $1001

    org $1001

; 10 GRAPHIC1:PRINT RLUM(1):SYS4119
pydis_start
basic_line_10
    da basic_end                                                      ; 1001: 15 10       ..
    da 10                                                             ; 1003: 0a 00       ..
    dfb $de                                                           ; 1005: de          .
    dfb $31, $3a ; petscii "1:"                                       ; 1006: 31 3a       1:
    dfb $99                                                           ; 1008: 99          .
    dfb $20 ; petscii " "                                             ; 1009: 20
    dfb $ce                                                           ; 100a: ce          N
    dfb $28, $31, $29, $3a ; petscii "(1):"                           ; 100b: 28 31 29... (1)
    dfb $9e                                                           ; 100f: 9e          .
    dfb $34, $31, $31, $39 ; petscii "4119"                           ; 1010: 34 31 31... 411
    dfb 0                                                             ; 1014: 00          .
basic_end
    da 0                                                              ; 1015: 00 00       ..

sys_entry
    rts                                                               ; 1017: 60          .

pydis_end

    err basic_end - $1015

; Stats:
;
;     Total size (Code + Data) = 23 bytes
;     Code                     = 1 bytes (4%)
;     Data                     = 22 bytes (96%)
;
;     Number of instructions   = 1
;     Number of data bytes     = 5 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 11 bytes
;     Number of strings        = 4
