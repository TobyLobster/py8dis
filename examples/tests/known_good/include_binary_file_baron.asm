; Assemble with Baron, which writes the program to the file named in its
; section (include_binary_file_baron), in the folder given with -p:
;     baron -p . include_binary_file_baron.asm

section pydis, org = &0e00, filename = "include_binary_file_baron"

.pydis_start
    equs "Hello"                                                      ; 0e00: 48 65 6c... Hel
    incbin "../orig/include_binary_data.bin"
    equs " world"                                                     ; 0e0d: 20 77 6f...  wo
.pydis_end


endsection

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
