; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
free_zero_page  equ $fb

; Vectors ($0300-$0333)
basic_error_vector  equ $0300

; 1541 drive
buffer_0 equ $0300

; The PRG file's header: the address to load it at
    org $07ff
    da $0801

    org $0801

; 10 SYS2061
pydis_start
basic_line_10
    da basic_end                                                      ; 0801: 0b 08       ..
    da 10                                                             ; 0803: 0a 00       ..
    dfb $9e                                                           ; 0805: 9e          .
    dfb $32, $30, $36, $31 ; petscii "2061"                           ; 0806: 32 30 36... 206
    dfb 0                                                             ; 080a: 00          .
basic_end
    da 0                                                              ; 080b: 00 00       ..

sys_entry
    lda basic_error_vector                                            ; 080d: ad 00 03    ...
    sta free_zero_page                                                ; 0810: 85 fb       ..
    rts                                                               ; 0812: 60          .


; Move 1: $0813 to $0500 for length 7
    org $0500
    lda buffer_0                                                      ; 0813: ad 00 03    ... :0500[1]
    sta buffer_0+1                                                    ; 0816: 8d 01 03    ... :0503[1]
    rts                                                               ; 0819: 60          .   :0506[1]

    org $081a

pydis_end

    err basic_end - $080b

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
