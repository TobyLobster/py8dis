; Assemble with Baron, which writes the program to the file named in its
; section (string_stuff1_baron), in the folder given with -p:
;     baron -p . string_stuff1_baron.asm

; Constants
page    = "1900"

section pydis, org = &0e00, filename = "string_stuff1_baron"

.pydis_start
    equs page                                                         ; 0e00: 31 39 30... 190
    equb &21                                                          ; 0e04: 21          !
.pydis_end


endsection

; Stats:
;
;     Total size (Code + Data) = 5 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 5 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1
