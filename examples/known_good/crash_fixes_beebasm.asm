; Constants
five    = 5
three   = 3

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070

; Other
before_banks = &7fff

    org &2000

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
    org &8000
    equb 1, 2, 3, 4                                                   ; 2015: 01 02 03... ... :8000[1]

    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock &8000, *, &2015

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear &8000, &8004

    ; Set the program counter to the next position in the binary file.
    org &2015 + (* - &8000)


; Move 2: &2019 to &8000 for length 4
    org &8000
    equb 5, 6, 7, 8                                                   ; 2019: 05 06 07... ... :8000[2]

    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock &8000, *, &2019

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear &8000, &8004

    ; Set the program counter to the next position in the binary file.
    org &2019 + (* - &8000)

.pydis_end


save pydis_start, pydis_end

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
;     Total size (Code + Data) = 29 bytes
;     Code                     = 15 bytes (52%)
;     Data                     = 14 bytes (48%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 14 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

