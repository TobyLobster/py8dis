; Constants
low_seven_bits  EQU 127
x_val           EQU 240
y_val           EQU 60

; Memory locations

    ORG $1000

pydis_start:
    mvi a, ~low_seven_bits & $ff                                      ; 1000: 3e 80       >.
    ani x_val & y_val                                                 ; 1002: e6 30       .0
    ori x_val | y_val                                                 ; 1004: f6 fc       ..
    xri x_val ^ y_val                                                 ; 1006: ee cc       ..
    mvi b, x_val / 16                                                 ; 1008: 06 0f       ..
    mvi c, x_val % 7                                                  ; 100a: 0e 02       ..
    ret                                                               ; 100c: c9          .

pydis_end:

; ASSERT ((x_val % 7) == $02)
; ASSERT ((x_val & y_val) == $30)
; ASSERT ((x_val / 16) == $0f)
; ASSERT ((x_val ^ y_val) == $cc)
; ASSERT ((x_val | y_val) == $fc)
; ASSERT ((~low_seven_bits & $ff) == $80)

; Stats:
;
;     Total size (Code + Data) = 13 bytes
;     Code                     = 13 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

