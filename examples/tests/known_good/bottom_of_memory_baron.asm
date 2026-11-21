; Assemble with Baron, which writes the program to the file named in its
; section (bottom_of_memory_baron), in the folder given with -p:
;     baron -p . bottom_of_memory_baron.asm

section pydis, org = &0000, filename = "bottom_of_memory_baron"

.pydis_start
.start
    nop                                                               ; 0000: ea          .
    nop                                                               ; 0001: ea          .
    bmi P%-16                                                         ; 0002: 30 ee       0.
    rts                                                               ; 0004: 60          `

.pydis_end


endsection

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
