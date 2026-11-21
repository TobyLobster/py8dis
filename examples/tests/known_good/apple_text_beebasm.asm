; Constants
cr  = 141

; Memory locations
cout = &fded

    org &0800

.pydis_start
.start
    ldx #0                                                            ; 0800: a2 00       ".
; &0802 referenced 1 time by &080b
.loop_c0802
    lda message,x                                                     ; 0802: bd 35 08    =..
    beq c080d                                                         ; 0805: f0 06       p.
    jsr cout                                                          ; 0807: 20 ed fd    .m}
    inx                                                               ; 080a: e8          h
    bne loop_c0802                                                    ; 080b: d0 f5       Pu
; &080d referenced 1 time by &0805
.c080d
    lda #'A' or &80                                                   ; 080d: a9 c1       )A
    jsr cout                                                          ; 080f: 20 ed fd    .m}
    lda #&a2 ; '"'                                                    ; 0812: a9 a2       )"
    jsr cout                                                          ; 0814: 20 ed fd    .m}
    lda #cr                                                           ; 0817: a9 8d       ).
    jsr cout                                                          ; 0819: 20 ed fd    .m}
    ldx #0                                                            ; 081c: a2 00       ".
; &081e referenced 1 time by &0829
.loop_c081e
    lda dci_message,x                                                 ; 081e: bd 4d 08    =..
    php                                                               ; 0821: 08          .
    ora #&80                                                          ; 0822: 09 80       ..
    jsr cout                                                          ; 0824: 20 ed fd    .m}
    inx                                                               ; 0827: e8          h
    plp                                                               ; 0828: 28          .
    bmi loop_c081e                                                    ; 0829: 30 f3       .s
    lda line                                                          ; 082b: ad 51 08    -..
    ldx ascii_message                                                 ; 082e: ae 56 08    ...
    ldy found_by_itself                                               ; 0831: ac 60 08    ,..
    rts                                                               ; 0834: 60          .

; &0835 referenced 1 time by &0802
.message
    equb &d3, &c1, &d9, &a0, &a2, &c8, &c9 ; apple "SAY ", &a2, "HI"  ; 0835: d3 c1 d9... SAY
    equb &a2, &a0, &d4, &cf, &a0, &dc, &c1 ; apple &a2, " TO \A"      ; 083c: a2 a0 d4... " T
    equb &d0, &d0, &cc, &c5, &a0, &c9, &c9, &a1 ; apple "PPLE II!"    ; 0843: d0 d0 cc... PPL
    equb &8d, 0 ; apple &8d, &00                                      ; 084b: 8d 00       ..
; &084d referenced 1 time by &081e
.dci_message
    equb &c4, &cf, &ce, &45 ; apple "DON", &45                        ; 084d: c4 cf ce... DON
; &0851 referenced 1 time by &082b
.line
    equb &cc, &c9, &ce, &c5, cr ; apple "LINE", &8d                   ; 0851: cc c9 ce... LIN
; &0856 referenced 1 time by &082e
.ascii_message
    equs "low ASCII", 0                                               ; 0856: 6c 6f 77... low
; &0860 referenced 1 time by &0831
.found_by_itself
    equb &c6, &cf, &d5, &ce, &c4, &a0, &c2, &d9 ; apple "FOUND BY"    ; 0860: c6 cf d5... FOU
    equb &a0, &c9, &d4, &d3, &c5, &cc, &c6 ; apple " ITSELF"          ; 0868: a0 c9 d4...  IT
    equb 0                                                            ; 086f: 00          .
.pydis_end


save pydis_start, pydis_end

; Label references by decreasing frequency:
;     cout:              5
;     ascii_message:     1
;     c080d:             1
;     dci_message:       1
;     found_by_itself:   1
;     line:              1
;     loop_c0802:        1
;     loop_c081e:        1
;     message:           1

; Automatically generated labels:
;     c080d
;     loop_c0802
;     loop_c081e

; Stats:
;
;     Total size (Code + Data) = 112 bytes
;     Code                     = 53 bytes (47%)
;     Data                     = 59 bytes (53%)
;
;     Number of instructions   = 24
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 58 bytes
;     Number of strings        = 5

