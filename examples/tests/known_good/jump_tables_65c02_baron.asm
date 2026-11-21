; Assemble with Baron, which writes the program to the file named in its
; section (jump_tables_65c02_baron), in the folder given with -p:
;     baron -p . jump_tables_65c02_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070
l0071   = &0071

section pydis, org = &2000, filename = "jump_tables_65c02_baron", cmos = true

.pydis_start
.start
    lda l0070                                                         ; 2000: a5 70       .p
    and #3                                                            ; 2002: 29 03       ).
    asl a                                                             ; 2004: 0a          .
    tax                                                               ; 2005: aa          .
    jmp (l2009,x)                                                     ; 2006: 7c 09 20    |.

; A jump table of 4 entries (for the JMP at &2006)
; &2009 referenced 1 time by &2006
.l2009
    equw sub_c2011                                                    ; 2009: 11 20       .
    equw sub_c2014                                                    ; 200b: 14 20       .
    equw sub_c2017                                                    ; 200d: 17 20       .
    equw sub_c201a                                                    ; 200f: 1a 20       .

.sub_c2011
    lda #&0a                                                          ; 2011: a9 0a       ..
    rts                                                               ; 2013: 60          `

.sub_c2014
    lda #&0b                                                          ; 2014: a9 0b       ..
    rts                                                               ; 2016: 60          `

.sub_c2017
    lda #&0c                                                          ; 2017: a9 0c       ..
    rts                                                               ; 2019: 60          `

.sub_c201a
    lda #&0d                                                          ; 201a: a9 0d       ..
    rts                                                               ; 201c: 60          `

.unguarded
    ldx l0071                                                         ; 201d: a6 71       .q
    jmp (l2022,x)                                                     ; 201f: 7c 22 20    |"

; &2022 referenced 1 time by &201f
.l2022
    equs "& ) "                                                       ; 2022: 26 20 29... & )
    equb &a9, &0e, &60, &a9, &0f, &60                                 ; 2026: a9 0e 60... ..`
.pydis_end

    assert (sub_c2011) = &2011
    assert (sub_c2014) = &2014
    assert (sub_c2017) = &2017
    assert (sub_c201a) = &201a

endsection

; Label references by decreasing frequency:
;     l0070:   1
;     l0071:   1
;     l2009:   1
;     l2022:   1

; Automatically generated labels:
;     l0070
;     l0071
;     l2009
;     l2022
;     sub_c2011
;     sub_c2014
;     sub_c2017
;     sub_c201a

; Stats:
;
;     Total size (Code + Data) = 44 bytes
;     Code                     = 26 bytes (59%)
;     Data                     = 18 bytes (41%)
;
;     Number of instructions   = 15
;     Number of data bytes     = 6 bytes
;     Number of data words     = 8 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1
