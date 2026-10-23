; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070

    org &2000

.pydis_start
.start
    jsr sub_cfff0                                                     ; 2000: 20 f0 ff     ..
    lda l0070                                                         ; 2003: a5 70       .p
    rts                                                               ; 2005: 60          `

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea             ; 2006: ea ea ea... ...

; Move 1: &2010 to &fff0 for length 16
    org &fff0
; &2010 referenced 1 time by &2000
.sub_cfff0
    lda #1                                                            ; 2010: a9 01       ..  :fff0[1]
    sta l0070                                                         ; 2012: 85 70       .p  :fff2[1]
    rts                                                               ; 2014: 60          `   :fff4[1]

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea        ; 2015: ea ea ea... ... :fff5[1]

    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock sub_cfff0, *-1, &2010

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear sub_cfff0, &10000

    ; Set the program counter to the next position in the binary file.
    org &201f
    equb &ea     ; The last byte of the block (not copied above, as the block reaches the top of memory)

.pydis_end


save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l0070:       2
;     sub_cfff0:   1

; Automatically generated labels:
;     l0070
;     sub_cfff0

; Stats:
;
;     Total size (Code + Data) = 32 bytes
;     Code                     = 11 bytes (34%)
;     Data                     = 21 bytes (66%)
;
;     Number of instructions   = 6
;     Number of data bytes     = 21 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

