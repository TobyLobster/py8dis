    org $0100

pydis_start:
start:
    lxi hl, $0114                                                     ; 0100: 21 14 01    !..
    lxi de, $8000                                                     ; 0103: 11 00 80    ...
    mvi b, $0c                                                        ; 0106: 06 0c       ..
; $0108 referenced 1 time by $010d
loop_c0108:
    mov a, m                                                          ; 0108: 7e          ~
    stax d                                                            ; 0109: 12          .
    inx h                                                             ; 010a: 23          #
    inx d                                                             ; 010b: 13          .
    dcr b                                                             ; 010c: 05          .
    jnz loop_c0108                                                    ; 010d: c2 08 01    ...
    call c8000                                                        ; 0110: cd 00 80    ...
    hlt                                                               ; 0113: 76          v

; Move 1: $0114 to $8000 for length 12
    phase $8000
; $0114 referenced 1 time by $0110
c8000:
    lxi hl, $0120 ; ' '                                               ; 0114: 21 20 01    ! . :8000[1]
    mvi b, 4                                                          ; 0117: 06 04       ..  :8003[1]
; $0119 referenced 1 time by $8008[1]
loop_c8005:
    mov a, m                                                          ; 0119: 7e          ~   :8005[1]
    inx h                                                             ; 011a: 23          #   :8006[1]
    dcr b                                                             ; 011b: 05          .   :8007[1]
    jnz loop_c8005                                                    ; 011c: c2 05 80    ... :8008[1]
    ret                                                               ; 011f: c9          .   :800b[1]

    dephase

    binary "orig/move_8080_table.bin"
pydis_end:


; Label references by decreasing frequency:
;     c8000:        1
;     loop_c0108:   1
;     loop_c8005:   1

; Automatically generated labels:
;     c8000
;     loop_c0108
;     loop_c8005

; Stats:
;
;     Total size (Code + Data) = 36 bytes
;     Code                     = 32 bytes (89%)
;     Data                     = 4 bytes (11%)
;
;     Number of instructions   = 18
;     Number of data bytes     = 4 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

