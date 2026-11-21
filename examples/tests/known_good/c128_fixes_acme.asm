; Memory locations

; Zero page ($0000-$00ff)
l00fb   = $fb

; MMU ($ff00-$ff04)
mmu_configuration   = $ff00

; Other banks
ld000   = $d000

; The PRG file's header: the address to load it at
    * = $1bff
    !word $1c01

    * = $1c01

; 10 BANK15:FAST:SYS7205
pydis_start
basic_line_10
    !word basic_line_20                                               ; 1c01: 13 1c       ..
    !word 10                                                          ; 1c03: 0a 00       ..
    !byte $fe                                                         ; 1c05: fe          .
    !byte 2                                                           ; 1c06: 02          .
    !pet "15:"                                                        ; 1c07: 31 35 3a    15:
    !byte $fe                                                         ; 1c0a: fe          .
    !pet "%:"                                                         ; 1c0b: 25 3a       %:
    !byte $9e                                                         ; 1c0d: 9e          .
    !pet "7205"                                                       ; 1c0e: 37 32 30... 720
    !byte 0                                                           ; 1c12: 00          .
; 20 PRINTXOR(1,2):GRAPHIC1
basic_line_20
    !word basic_end                                                   ; 1c13: 23 1c       #.
    !word 20                                                          ; 1c15: 14 00       ..
    !byte $99                                                         ; 1c17: 99          .
    !byte $ce                                                         ; 1c18: ce          N
    !byte 8                                                           ; 1c19: 08          .
    !pet "(1,2):"                                                     ; 1c1a: 28 31 2c... (1,
    !byte $de                                                         ; 1c20: de          .
    !pet "1"                                                          ; 1c21: 31          1
    !byte 0                                                           ; 1c22: 00          .
basic_end
    !word 0                                                           ; 1c23: 00 00       ..

sys_entry
    lda #$17                                                          ; 1c25: a9 17       ..
    sta mmu_configuration                                             ; 1c27: 8d 00 ff    ... ; Set the MMU to RAM 0, internal function ROM at $8000-$ffff
    lda ld000                                                         ; 1c2a: ad 00 d0    ..P
    sta l00fb                                                         ; 1c2d: 85 fb       ..
    lda #0                                                            ; 1c2f: a9 00       ..
    sta mmu_configuration                                             ; 1c31: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    rts                                                               ; 1c34: 60          .

pydis_end

!if (basic_end) != $1c23 {
    !error "Assertion failed: basic_end == $1c23"
}
!if (basic_line_20) != $1c13 {
    !error "Assertion failed: basic_line_20 == $1c13"
}

; Label references by decreasing frequency:
;     mmu_configuration:   2
;     l00fb:               1
;     ld000:               1

; Automatically generated labels:
;     l00fb

; Stats:
;
;     Total size (Code + Data) = 52 bytes
;     Code                     = 16 bytes (31%)
;     Data                     = 36 bytes (69%)
;
;     Number of instructions   = 7
;     Number of data bytes     = 10 bytes
;     Number of data words     = 10 bytes
;     Number of string bytes   = 16 bytes
;     Number of strings        = 5

