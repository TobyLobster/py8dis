; Constants
addr_val        equ 4660
low_seven_bits  equ 127
x_val           equ 240
y_val           equ 60

    org $1000

pydis_start:
    mvi a, ~low_seven_bits & $ff                                      ; 1000: 3e 80       >.
    ani x_val & y_val                                                 ; 1002: e6 30       .0
    ori x_val | y_val                                                 ; 1004: f6 fc       ..
    xri x_val ^ y_val                                                 ; 1006: ee cc       ..
    mvi b, x_val / 16                                                 ; 1008: 06 0f       ..
    mvi c, x_val % 7                                                  ; 100a: 0e 02       ..
    mvi d, addr_val & $ff                                             ; 100c: 16 34       .4
    mvi e, addr_val >> 8                                              ; 100e: 1e 12       ..
    mvi h, +(addr_val + 1) & $ff                                      ; 1010: 26 35       &5
    lxi bc, +(addr_val + 1)                                           ; 1012: 01 35 12    .5.
    ret                                                               ; 1015: c9          .

pydis_end:

; ASSERT (((addr_val + 1)) == $1235)
; ASSERT (((addr_val + 1) & $ff) == $35)
; ASSERT ((addr_val & $ff) == $34)
; ASSERT ((addr_val >> 8) == $12)
; ASSERT ((x_val % 7) == $02)
; ASSERT ((x_val & y_val) == $30)
; ASSERT ((x_val / 16) == $0f)
; ASSERT ((x_val ^ y_val) == $cc)
; ASSERT ((x_val | y_val) == $fc)
; ASSERT ((~low_seven_bits & $ff) == $80)

; Stats:
;
;     Total size (Code + Data) = 22 bytes
;     Code                     = 22 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 11
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

