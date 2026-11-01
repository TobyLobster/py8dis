; Memory locations

; Zero page (&0000-&00ff)
free_zero_page  = &00fb

; Vectors (&0300-&0333)
basic_error_vector  = &0300

; 1541 drive
buffer_0 = &0300

; The PRG file's header: the address to load it at
    org &07ff
    equw &0801

    org &0801

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
    org &0500
    lda buffer_0                                                      ; 0813: ad 00 03    ... :0500[1]
    sta buffer_0+1                                                    ; 0816: 8d 01 03    ... :0503[1]
    rts                                                               ; 0819: 60          .   :0506[1]


    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock &0500, *, &0813

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear &0500, &0507

    ; Set the program counter to the next position in the binary file.
    org &0813 + (* - &0500)

.pydis_end

    assert &080b == basic_end

save pydis_start - 2, pydis_end

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

