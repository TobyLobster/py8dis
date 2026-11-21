; Assemble with Baron, which writes the program to the file named in its
; section (atom_basic_baron), in the folder given with -p:
;     baron -p . atom_basic_baron.asm

; Memory locations

; OS entry points (&ffcb-&fff9)
OSWRCH  = &fff4

; The ATM file's header
section pydis, org = &28ea, filename = "atom_basic_baron"
    equb &42, &41, &53, &49, &43, &20, &54, &45, &53, &54, 0, 0, 0, 0, 0, 0 ; Name: "BASIC TEST"
    equw &2900 ; Load address
    equw &c2b2 ; Execution address
    equw &0056 ; Length

.pydis_start
.basic_start
    equb &0d                                                          ; 2900: 0d          .
; 10 REM AN ATOM BASIC PROGRAM
.basic_line_10
    equb 0, 10                                                        ; 2901: 00 0a       ..
    equs "REM AN ATOM BASIC PROGRAM"                                  ; 2903: 52 45 4d... REM
    equb &0d                                                          ; 291c: 0d          .
; 20 P."HELLO, WORLD"
.basic_line_20
    equb 0, 20                                                        ; 291d: 00 14       ..
    equs "P.""HELLO, WORLD"""                                         ; 291f: 50 2e 22... P."
    equb &0d                                                          ; 292f: 0d          .
; 300 LINK #2950
.basic_line_300
    equb 1, 44                                                        ; 2930: 01 2c       .,
    equs "LINK #2950"                                                 ; 2932: 4c 49 4e... LIN
    equb &0d                                                          ; 293c: 0d          .
; 310 E.
.basic_line_310
    equb 1, 54                                                        ; 293d: 01 36       .6
    equs "E."                                                         ; 293f: 45 2e       E.
    equb &0d                                                          ; 2941: 0d          .
.basic_end
    equb &ff                                                          ; 2942: ff          .
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0                        ; 2943: 00 00 00... ...

.link_entry
    lda #&41 ; 'A'                                                    ; 2950: a9 41       .A
    jsr OSWRCH                                                        ; 2952: 20 f4 ff     .. ; Write character 65
    rts                                                               ; 2955: 60          `

.pydis_end


endsection

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
