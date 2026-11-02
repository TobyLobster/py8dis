; Constants
finish_offset   equ 26

    org $00

pydis_start:
start:
    jmp c000b                                                         ; 0000: c3 0b 00    ...

    db 0, 0, 0, 0, 0                                                  ; 0003: 00 00 00... ...

; ***************************************************************************************
; Set A to 1
; ***************************************************************************************
; $08 referenced 1 time by $0b
rst_08:
    mvi a, 1                                                          ; 0008: 3e 01       >.
    ret                                                               ; 000a: c9          .

; $0b referenced 1 time by $00
c000b:
    rst $08                                                           ; 000b: cf          .  ; Set A to 1
    lxi h, $0120                                                      ; 000c: 21 20 01    ! .
    lxi b, $41 ; 'A'                                                  ; 000f: 01 41 00    .A.
    cpi 0                                                             ; 0012: fe 00       ..
    jz start + finish_offset                                          ; 0014: ca 1a 00    ... ; Finish, with Z unknown
    call sub_c001b                                                    ; 0017: cd 1b 00    ... ; Increment A
; ***************************************************************************************
; $1a referenced 1 time by $14
finish:
    hlt                                                               ; 001a: 76          v
; ***************************************************************************************
; Increment A
; ***************************************************************************************
; $1b referenced 1 time by $17
sub_c001b:
    inr a                                                             ; 001b: 3c          <
    ret                                                               ; 001c: c9          .

pydis_end:

; ASSERT ((start + finish_offset) == $1a)

; Label references by decreasing frequency:
;     c000b:       1
;     finish:      1
;     rst_08:      1
;     sub_c001b:   1

; Automatically generated labels:
;     c000b
;     rst_08
;     sub_c001b

; Stats:
;
;     Total size (Code + Data) = 29 bytes
;     Code                     = 24 bytes (83%)
;     Data                     = 5 bytes (17%)
;
;     Number of instructions   = 12
;     Number of data bytes     = 5 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

