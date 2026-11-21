; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Zero page ($00-$ff)
l00fb   equ $fb

; MMU ($ff00-$ff04)
mmu_configuration   equ $ff00

; Other banks
ld000   equ $d000

; The PRG file's header: the address to load it at
    org $1bff
    da $1c01

    org $1c01

; 10 BANK15:FAST:SYS7205
pydis_start
basic_line_10
    da basic_line_20                                                  ; 1c01: 13 1c       ..
    da 10                                                             ; 1c03: 0a 00       ..
    dfb $fe                                                           ; 1c05: fe          .
    dfb 2                                                             ; 1c06: 02          .
    dfb $31, $35, $3a ; petscii "15:"                                 ; 1c07: 31 35 3a    15:
    dfb $fe                                                           ; 1c0a: fe          .
    dfb $25, $3a ; petscii "%:"                                       ; 1c0b: 25 3a       %:
    dfb $9e                                                           ; 1c0d: 9e          .
    dfb $37, $32, $30, $35 ; petscii "7205"                           ; 1c0e: 37 32 30... 720
    dfb 0                                                             ; 1c12: 00          .
; 20 PRINTXOR(1,2):GRAPHIC1
basic_line_20
    da basic_end                                                      ; 1c13: 23 1c       #.
    da 20                                                             ; 1c15: 14 00       ..
    dfb $99                                                           ; 1c17: 99          .
    dfb $ce                                                           ; 1c18: ce          N
    dfb 8                                                             ; 1c19: 08          .
    dfb $28, $31, $2c, $32, $29, $3a ; petscii "(1,2):"               ; 1c1a: 28 31 2c... (1,
    dfb $de                                                           ; 1c20: de          .
    dfb $31 ; petscii "1"                                             ; 1c21: 31          1
    dfb 0                                                             ; 1c22: 00          .
basic_end
    da 0                                                              ; 1c23: 00 00       ..

sys_entry
    lda #$17                                                          ; 1c25: a9 17       ..
    sta mmu_configuration                                             ; 1c27: 8d 00 ff    ... ; Set the MMU to RAM 0, internal function ROM at $8000-$ffff
    lda ld000                                                         ; 1c2a: ad 00 d0    ..P
    sta l00fb                                                         ; 1c2d: 85 fb       ..
    lda #0                                                            ; 1c2f: a9 00       ..
    sta mmu_configuration                                             ; 1c31: 8d 00 ff    ... ; Set the MMU to bank 15 (RAM 0, BASIC ROM, Kernal ROM, I/O)
    rts                                                               ; 1c34: 60          .

pydis_end

    err basic_end - $1c23
    err basic_line_20 - $1c13

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
