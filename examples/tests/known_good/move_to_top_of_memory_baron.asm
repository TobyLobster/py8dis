; Assemble with Baron, which writes the program to the file named in its
; section (move_to_top_of_memory_baron), in the folder given with -p:
;     baron -p . move_to_top_of_memory_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070

section pydis, org = &2000, filename = "move_to_top_of_memory_baron"

.pydis_start
.start
    jsr sub_cfff0                                                     ; 2000: 20 f0 ff     ..
    lda l0070                                                         ; 2003: a5 70       .p
    rts                                                               ; 2005: 60          `

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea             ; 2006: ea ea ea... ...

; Move 1: &2010 to &fff0 for length 16
    section move_1, org = &fff0
; &2010 referenced 1 time by &2000
.sub_cfff0
    lda #1                                                            ; 2010: a9 01       ..  :fff0[1]
    sta l0070                                                         ; 2012: 85 70       .p  :fff2[1]
    rts                                                               ; 2014: 60          `   :fff4[1]

    equb &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea, &ea        ; 2015: ea ea ea... ... :fff5[1]
    endsection

.pydis_end


endsection

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
