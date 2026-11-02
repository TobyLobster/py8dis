; Assemble with Baron, which writes the program to the file named in its
; section (cycles_65c02_baron), in the folder given with -p:
;     baron -p . cycles_65c02_baron.asm

; Memory locations

; Zero page (&0000-&00ff)
l0070   = &0070

; Other
l1200   = &1200
l1234   = &1234

section pydis, org = &2000, filename = "cycles_65c02_baron", cmos = true

.pydis_start
.start
    sed                                                               ; 2000: f8          .   2 cycles
    adc #1                                                            ; 2001: 69 01       i.  2/3 cycles
    sbc #1                                                            ; 2003: e9 01       ..  2/3 cycles
    sbc l1234                                                         ; 2005: ed 34 12    .4. 4/5 cycles
    sbc (l0070,x)                                                     ; 2008: e1 70       .p  6/7 cycles
    cld                                                               ; 200a: d8          .   2 cycles
    bit l1234,x                                                       ; 200b: 3c 34 12    <4. 4/5 cycles   ; Redundant instruction?
    bit l1200,x                                                       ; 200e: 3c 00 12    <.. 4 cycles
    asl l1234,x                                                       ; 2011: 1e 34 12    .4. 6/7 cycles
    rol l1200,x                                                       ; 2014: 3e 00 12    >.. 6 cycles
    bra return_1                                                      ; 2017: 80 00       ..  3 cycles

; &2019 referenced 1 time by &2017
.return_1
    rts                                                               ; 2019: 60          `   6 cycles

.pydis_end


endsection

; Label references by decreasing frequency:
;     l1234:      3
;     l1200:      2
;     l0070:      1
;     return_1:   1

; Automatically generated labels:
;     l0070
;     l1200
;     l1234
;     return_1

; Stats:
;
;     Total size (Code + Data) = 26 bytes
;     Code                     = 26 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 12
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
