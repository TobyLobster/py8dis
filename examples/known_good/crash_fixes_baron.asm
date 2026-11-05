; Assemble with Baron, which writes the program to the file named in its
; section (crash_fixes_baron), in the folder given with -p:
;     baron -p . crash_fixes_baron.asm

; Constants
five    = 5
three   = 3

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070

; Other
before_banks = &7fff

section pydis, org = &2000, filename = "crash_fixes_baron"

.pydis_start
.start
    equb &a9                                                          ; 2000: a9          .
    equb 1                                                            ; 2001: 01          .

    jsr sub_c200e                                                     ; 2002: 20 0e 20     .
    sta l0070                                                         ; 2005: 85 70       .p
    lda before_banks+1                                                ; 2007: ad 00 80    ...            ; Redundant instruction?
    lda l2011                                                         ; 200a: ad 11 20    ..
    rts                                                               ; 200d: 60          `

; &200e referenced 1 time by &2002
.sub_c200e
    lda #three                                                        ; 200e: a9 03       ..
    rts                                                               ; 2010: 60          `

; &2011 referenced 1 time by &200a
.l2011
    equb &34                                                          ; 2011: 34          4
    equb &12, &78, &56                                                ; 2012: 12 78 56    .xV

; Move 1: &2015 to &8000 for length 4
    section move_1, org = &8000
    equb 1, 2, 3, 4                                                   ; 2015: 01 02 03... ... :8000[1]
    endsection


; Move 2: &2019 to &8000 for length 4
    section move_2, org = &8000
    equb 5, 6, 7, 8                                                   ; 2019: 05 06 07... ... :8000[2]
    endsection

    equs "G", &80 + 'O'                                               ; 201d: 47 cf       G.
    equb >start, <start                                               ; 201f: 20 00        .
.pydis_end

    assert (&80 + 'O') = &cf
    assert (<start) = &00
    assert (>start) = &20

endsection

; Label references by decreasing frequency:
;     before_banks+1:   1
;     l0070:            1
;     l2011:            1
;     sub_c200e:        1

; Automatically generated labels:
;     l0070
;     l2011
;     sub_c200e

; Stats:
;
;     Total size (Code + Data) = 33 bytes
;     Code                     = 15 bytes (45%)
;     Data                     = 18 bytes (55%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 16 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 2 bytes
;     Number of strings        = 1
