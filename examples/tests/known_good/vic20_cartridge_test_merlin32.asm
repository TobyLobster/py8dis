; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; Vectors ($0300-$0333)
nmi_vector  equ $0318

; BASIC ROM ($c000-$dfff)
basic_warm_start_vector equ $c002

; Kernal ROM ($e000-$ff89)
CINT        equ $e518
RESTOR_ROM  equ $fd52
RAMTAS      equ $fd8d
IOINIT      equ $fdf9

; Kernal entry points ($ff8a-$fff9)
GETIN   equ $ffe4

    org $a000

; Cartridge header
pydis_start
cartridge_cold_start_vector
    da cartridge_cold_start                                           ; a000: 09 a0       ..
cartridge_warm_start_vector
    da cartridge_warm_start                                           ; a002: 24 a0       $.
cartridge_signature
    dfb $41, $30, $c3, $c2, $cd ; petscii "a0CBM"                     ; a004: 41 30 c3... a0C

cartridge_cold_start
    jsr RAMTAS                                                        ; a009: 20 8d fd     ..
    jsr RESTOR_ROM                                                    ; a00c: 20 52 fd     r.
    jsr IOINIT                                                        ; a00f: 20 f9 fd     ..
    jsr CINT                                                          ; a012: 20 18 e5     ..

    ; Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 ; a015: a2 27       .'
    ldy #>nmi_handler                                                 ; a017: a0 a0       ..
    stx nmi_vector                                                    ; a019: 8e 18 03    ...
    sty nmi_vector+1                                                  ; a01c: 8c 19 03    ...

; $a01f referenced 1 time by $a022
loop_ca01f
    jsr GETIN                                                         ; a01f: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq loop_ca01f                                                    ; a022: f0 fb       ..
cartridge_warm_start
    jmp (basic_warm_start_vector)                                     ; a024: 6c 02 c0    ...

nmi_handler
    rti                                                               ; a027: 40          @

pydis_end

    err nmi_handler & $ff - $27
    err nmi_handler & $ffff / $0100 - $a0
    err cartridge_cold_start - $a009
    err cartridge_warm_start - $a024

; Label references by decreasing frequency:
;     CINT:                      1
;     GETIN:                     1
;     IOINIT:                    1
;     RAMTAS:                    1
;     RESTOR_ROM:                1
;     basic_warm_start_vector:   1
;     loop_ca01f:                1
;     nmi_vector:                1

; Automatically generated labels:
;     loop_ca01f

; Stats:
;
;     Total size (Code + Data) = 40 bytes
;     Code                     = 31 bytes (78%)
;     Data                     = 9 bytes (22%)
;
;     Number of instructions   = 12
;     Number of data bytes     = 0 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1
