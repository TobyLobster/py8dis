; Assemble with Baron, which writes the program to the file named in its
; section (plus4_basic_baron), in the folder given with -p:
;     baron -p . plus4_basic_baron.asm

; The PRG file's header: the address to load it at
section pydis, org = &0fff, filename = "plus4_basic_baron"
    equw &1001

; 10 GRAPHIC1:PRINT RLUM(1):SYS4119
.pydis_start
.basic_line_10
    equw basic_end                                                    ; 1001: 15 10       ..
    equw 10                                                           ; 1003: 0a 00       ..
    equb &de                                                          ; 1005: de          .
    equb &31, &3a ; petscii "1:"                                      ; 1006: 31 3a       1:
    equb &99                                                          ; 1008: 99          .
    equb &20 ; petscii " "                                            ; 1009: 20
    equb &ce                                                          ; 100a: ce          N
    equb &28, &31, &29, &3a ; petscii "(1):"                          ; 100b: 28 31 29... (1)
    equb &9e                                                          ; 100f: 9e          .
    equb &34, &31, &31, &39 ; petscii "4119"                          ; 1010: 34 31 31... 411
    equb 0                                                            ; 1014: 00          .
.basic_end
    equw 0                                                            ; 1015: 00 00       ..

.sys_entry
    rts                                                               ; 1017: 60          .

.pydis_end

    assert (basic_end) = &1015

endsection

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
