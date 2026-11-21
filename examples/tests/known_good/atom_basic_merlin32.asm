; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; OS entry points ($ffcb-$fff9)
OSWRCH  equ $fff4

; The ATM file's header
    org $28ea
    dfb $42, $41, $53, $49, $43, $20, $54, $45, $53, $54, 0, 0, 0, 0, 0, 0 ; Name: "BASIC TEST"
    da $2900 ; Load address
    da $c2b2 ; Execution address
    da $56 ; Length

    org $2900

pydis_start
basic_start
    dfb $0d                                                           ; 2900: 0d          .
; 10 REM AN ATOM BASIC PROGRAM
basic_line_10
    dfb 0, 10                                                         ; 2901: 00 0a       ..
    asc 'REM AN ATOM BASIC PROGRAM'                                   ; 2903: 52 45 4d... REM
    dfb $0d                                                           ; 291c: 0d          .
; 20 P."HELLO, WORLD"
basic_line_20
    dfb 0, 20                                                         ; 291d: 00 14       ..
    asc 'P."HELLO, WORLD"'                                            ; 291f: 50 2e 22... P."
    dfb $0d                                                           ; 292f: 0d          .
; 300 LINK #2950
basic_line_300
    dfb 1, 44                                                         ; 2930: 01 2c       .,
    asc 'LINK #2950'                                                  ; 2932: 4c 49 4e... LIN
    dfb $0d                                                           ; 293c: 0d          .
; 310 E.
basic_line_310
    dfb 1, 54                                                         ; 293d: 01 36       .6
    asc 'E.'                                                          ; 293f: 45 2e       E.
    dfb $0d                                                           ; 2941: 0d          .
basic_end
    dfb $ff                                                           ; 2942: ff          .
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                         ; 2943: 00 00 00... ...

link_entry
    lda #$41 ; 'A'                                                    ; 2950: a9 41       .A
    jsr OSWRCH                                                        ; 2952: 20 f4 ff     .. ; Write character 65
    rts                                                               ; 2955: 60          `

pydis_end


; Label references by decreasing frequency:
;     OSWRCH:   1

; Stats:
;
;     Total size (Code + Data) = 86 bytes
;     Code                     = 6 bytes (7%)
;     Data                     = 80 bytes (93%)
;
;     Number of instructions   = 3
;     Number of data bytes     = 27 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 53 bytes
;     Number of strings        = 4
