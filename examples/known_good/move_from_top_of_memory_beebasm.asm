; Memory locations
l0070   = &0070

    org &ffe0

; &ffe0 referenced 1 time by &0900[1]
.pydis_start
    lda #1                                                            ; ffe0: a9 01       ..
    sta l0070                                                         ; ffe2: 85 70       .p
    rts                                                               ; ffe4: 60          `

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea        ; ffe5: ea ea ea... ...

; Move 1: &fff0 to &0900 for length 16
    org &0900
.start
    jsr pydis_start                                                   ; fff0: 20 e0 ff     .. :0900[1]
    lda l0070                                                         ; fff3: a5 70       .p  :0903[1]
    rts                                                               ; fff5: 60          `   :0905[1]

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea             ; fff6: ea ea ea... ... :0906[1]

    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock start, *-1, &fff0

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear start, &0910

    ; Set the program counter to the next position in the binary file.
    org &ffff
    equb &ea     ; The last byte of the block (not copied above, as the block reaches the top of memory)

.pydis_end


save pydis_start, pydis_end

; Label references by decreasing frequency:
;     l0070:         2
;     pydis_start:   1

; Automatically generated labels:
;     l0070

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

