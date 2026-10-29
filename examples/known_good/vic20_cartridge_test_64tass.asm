; Memory locations

; Vectors ($0300-$0333)
nmi_vector  = $0318

; BASIC ROM ($c000-$dfff)
basic_warm_start_vector = $c002

; Kernal ROM ($e000-$ff89)
cint        = $e518
restor_rom  = $fd52
ramtas      = $fd8d
ioinit      = $fdf9

; Kernal entry points ($ff8a-$fff9)
getin   = $ffe4

    * = $a000

; Cartridge header
pydis_start
cartridge_cold_start_vector
    .word cartridge_cold_start                                        ; a000: 09 a0       ..
cartridge_warm_start_vector
    .word cartridge_warm_start                                        ; a002: 24 a0       $.
cartridge_signature
    .byte $41, $30, $c3, $c2, $cd ; petscii "a0CBM"                   ; a004: 41 30 c3... a0C

cartridge_cold_start
    jsr ramtas                                                        ; a009: 20 8d fd     ..
    jsr restor_rom                                                    ; a00c: 20 52 fd     r.
    jsr ioinit                                                        ; a00f: 20 f9 fd     ..
    jsr cint                                                          ; a012: 20 18 e5     ..

    ; Set the NMI vector to nmi_handler
    ldx #<nmi_handler                                                 ; a015: a2 27       .'
    ldy #>nmi_handler                                                 ; a017: a0 a0       ..
    stx nmi_vector                                                    ; a019: 8e 18 03    ...
    sty nmi_vector+1                                                  ; a01c: 8c 19 03    ...

; $a01f referenced 1 time by $a022
loop_ca01f
    jsr getin                                                         ; a01f: 20 e4 ff     .. ; Get a character from the input channel (from the keyboard, 0 if there's none)
    beq loop_ca01f                                                    ; a022: f0 fb       ..
cartridge_warm_start
    jmp (basic_warm_start_vector)                                     ; a024: 6c 02 c0    ...

nmi_handler
    rti                                                               ; a027: 40          @

pydis_end

.cerror (<nmi_handler) != $27, "Assertion failed: <nmi_handler == $27"
.cerror (>nmi_handler) != $a0, "Assertion failed: >nmi_handler == $a0"
.cerror (cartridge_cold_start) != $a009, "Assertion failed: cartridge_cold_start == $a009"
.cerror (cartridge_warm_start) != $a024, "Assertion failed: cartridge_warm_start == $a024"

; Label references by decreasing frequency:
;     basic_warm_start_vector:   1
;     cint:                      1
;     getin:                     1
;     ioinit:                    1
;     loop_ca01f:                1
;     nmi_vector:                1
;     ramtas:                    1
;     restor_rom:                1

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

