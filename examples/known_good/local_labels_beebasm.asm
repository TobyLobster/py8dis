; Memory locations
char_to_print   = &0070
bit_value       = &0070
oswrch          = &ffee

    org &2000

; output some characters
.pydis_start
    lda #5                                                            ; 2000: a9 05       ..
    sta char_to_print                                                 ; 2002: 85 70       .p
    ldx #&0a                                                          ; 2004: a2 0a       ..
.print_loop
    lda #'A'                                                          ; 2006: a9 41       .A
    clc                                                               ; 2008: 18          .
    adc char_to_print                                                 ; 2009: 65 70       ep
    jsr oswrch                                                        ; 200b: 20 ee ff     ..
    inc char_to_print                                                 ; 200e: e6 70       .p
    inc char_to_print                                                 ; 2010: e6 70       .p
    dex                                                               ; 2012: ca          .
    bne print_loop                                                    ; 2013: d0 f1       ..

; count bits in a byte
    lda #&14                                                          ; 2015: a9 14       ..
    sta bit_value                                                     ; 2017: 85 70       .p
.bit_counting_loop
    lsr bit_value                                                     ; 2019: 46 70       Fp
    bcc skip_add_to_bit_count                                         ; 201b: 90 01       ..
    inx                                                               ; 201d: e8          .
.skip_add_to_bit_count
    lda bit_value                                                     ; 201e: a5 70       .p
    bne bit_counting_loop                                             ; 2020: d0 f7       ..
    rts                                                               ; 2022: 60          `

.pydis_end

save pydis_start, pydis_end
