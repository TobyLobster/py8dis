; Assemble with Baron, which writes the program to the file named in its
; section (top_of_memory_string_baron), in the folder given with -p:
;     baron -p . top_of_memory_string_baron.asm

section pydis, org = &ffe0, filename = "top_of_memory_string_baron"

.pydis_start
    equb &a2, &80                                                     ; ffe0: a2 80       ..
    equs "0<L"                                                        ; ffe2: 30 3c 4c    0<L
    equb &fd, &ff                                                     ; ffe5: fd ff       ..
    equs "THE TOP OF MEMORY"                                          ; ffe7: 54 48 45... THE
    equb 0, 0, 0, 0, 0                                                ; fff8: 00 00 00... ...
    equs ",,A"                                                        ; fffd: 2c 2c 41    ,,A
.pydis_end


endsection

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
