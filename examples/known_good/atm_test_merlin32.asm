; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; OS entry points ($ffcb-$fff9)
OSWRCH  equ $fff4

; The ATM file's header
    org $28ea
    dfb $41, $54, $4d, $20, $54, $45, $53, $54, 0, 0, 0, 0, 0, 0, 0, 0 ; Name: "ATM TEST"
    da $2900 ; Load address
    da $2906 ; Execution address
    da $14 ; Length

    org $2900

; $2900 referenced 1 time by $2908
pydis_start
    asc 'HELLO'                                                       ; 2900: 48 45 4c... HEL
    dfb $0d                                                           ; 2905: 0d          .

; The ATM file's execution address
    ; print message
    ldx #0                                                            ; 2906: a2 00       ..
; $2908 referenced 1 time by $2911
loop_c2908
    lda pydis_start,x                                                 ; 2908: bd 00 29    ..)
    jsr OSWRCH                                                        ; 290b: 20 f4 ff     .. ; Write character
    inx                                                               ; 290e: e8          .
    cpx #6                                                            ; 290f: e0 06       ..
    bne loop_c2908                                                    ; 2911: d0 f5       ..
    rts                                                               ; 2913: 60          `

pydis_end


; Label references by decreasing frequency:
;     OSWRCH:        1
;     loop_c2908:    1
;     pydis_start:   1

; Automatically generated labels:
;     loop_c2908

; Stats:
;
;     Total size (Code + Data) = 20 bytes
;     Code                     = 14 bytes (70%)
;     Data                     = 6 bytes (30%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 1 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1
