; Assemble with Baron, which writes the program to the file named in its
; section (drive_code_names_baron), in the folder given with -p:
;     baron -p . drive_code_names_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
free_zero_page  = &00fb

; Vectors (&0300-&0333)
basic_error_vector  = &0300

; 1541 drive
buffer_0 = &0300

; The PRG file's header: the address to load it at
section pydis, org = &07ff, filename = "drive_code_names_baron"
    equw &0801

; 10 SYS2061
.pydis_start
.basic_line_10
    equw basic_end                                                    ; 0801: 0b 08       ..
    equw 10                                                           ; 0803: 0a 00       ..
    equb &9e                                                          ; 0805: 9e          .
    equb &32, &30, &36, &31 ; petscii "2061"                          ; 0806: 32 30 36... 206
    equb 0                                                            ; 080a: 00          .
.basic_end
    equw 0                                                            ; 080b: 00 00       ..

.sys_entry
    lda basic_error_vector                                            ; 080d: ad 00 03    ...
    sta free_zero_page                                                ; 0810: 85 fb       ..
    rts                                                               ; 0812: 60          .


; Move 1: &0813 to &0500 for length 7
    section move_1, org = &0500
    lda buffer_0                                                      ; 0813: ad 00 03    ... :0500[1]
    sta buffer_0+1                                                    ; 0816: 8d 01 03    ... :0503[1]
    rts                                                               ; 0819: 60          .   :0506[1]

    endsection

.pydis_end

    assert (basic_end) = &080b

endsection

; Label references by decreasing frequency:
;     basic_error_vector:   2
;     buffer_0:             2
;     free_zero_page:       1

; Stats:
;
;     Total size (Code + Data) = 25 bytes
;     Code                     = 13 bytes (52%)
;     Data                     = 12 bytes (48%)
;
;     Number of instructions   = 6
;     Number of data bytes     = 2 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1
