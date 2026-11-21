    * = $20f0

pydis_start
start
    ldx #3                                                            ; 20f0: a2 03       ..  2 cycles
    nop                                                               ; 20f2: ea          .   2 cycles
    nop                                                               ; 20f3: ea          .   2 cycles
    nop                                                               ; 20f4: ea          .   2 cycles
    nop                                                               ; 20f5: ea          .   2 cycles
    nop                                                               ; 20f6: ea          .   2 cycles
    nop                                                               ; 20f7: ea          .   2 cycles
    nop                                                               ; 20f8: ea          .   2 cycles
    nop                                                               ; 20f9: ea          .   2 cycles
    nop                                                               ; 20fa: ea          .   2 cycles
    nop                                                               ; 20fb: ea          .   2 cycles
    nop                                                               ; 20fc: ea          .   2 cycles
    nop                                                               ; 20fd: ea          .   2 cycles
    dex                                                               ; 20fe: ca          .   2 cycles                 ; X=2
    bne c2101                                                         ; 20ff: d0 00       ..  2/3 cycles               ; ALWAYS branch

; $2101 referenced 1 time by $20ff
c2101
    jsr sub_c30fe                                                     ; 2101: 20 fe 30     .0 6 cycles
    rts                                                               ; 2104: 60          `   6 cycles


; Move 1: $2105 to $30fe for length 5
.logical $30fe
; $2105 referenced 1 time by $2101
sub_c30fe
    bne return_1                                                      ; 2105: d0 02       ..  2/3 cycles    :30fe[1]
    nop                                                               ; 2107: ea          .   2 cycles      :3100[1]
    nop                                                               ; 2108: ea          .   2 cycles      :3101[1]
; $2109 referenced 1 time by $30fe[1]
return_1
    rts                                                               ; 2109: 60          `   6 cycles      :3102[1]

.here

pydis_end


; Label references by decreasing frequency:
;     c2101:       1
;     return_1:    1
;     sub_c30fe:   1

; Automatically generated labels:
;     c2101
;     return_1
;     sub_c30fe

; Stats:
;
;     Total size (Code + Data) = 26 bytes
;     Code                     = 26 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 21
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

