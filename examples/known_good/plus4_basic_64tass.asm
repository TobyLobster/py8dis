; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; The PRG file's header: the address to load it at
    * = $0fff
    .word $1001

    * = $1001

; 10 GRAPHIC1:PRINT RLUM(1):SYS4119
pydis_start
basic_line_10
    .word basic_end                                                   ; 1001: 15 10       ..
    .word 10                                                          ; 1003: 0a 00       ..
    .byte $de                                                         ; 1005: de          .
    .text "1:"                                                        ; 1006: 31 3a       1:
    .byte $99                                                         ; 1008: 99          .
    .text " "                                                         ; 1009: 20
    .byte $ce                                                         ; 100a: ce          N
    .text "(1):"                                                      ; 100b: 28 31 29... (1)
    .byte $9e                                                         ; 100f: 9e          .
    .text "4119"                                                      ; 1010: 34 31 31... 411
    .byte 0                                                           ; 1014: 00          .
basic_end
    .word 0                                                           ; 1015: 00 00       ..

sys_entry
    rts                                                               ; 1017: 60          .

pydis_end

.cerror (basic_end) != $1015, "Assertion failed: basic_end == $1015"

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

