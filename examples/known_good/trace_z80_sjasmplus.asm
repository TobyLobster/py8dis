; Assemble with sjasmplus, to a plain binary:
;     sjasmplus --nologo --raw=program.bin this_file.asm

; Constants
copy_to     equ $8000
count       equ 3
ula_port    equ $fe

    org $00

pydis_start:
start:
    di                                                                ; 0000: f3          .   4 cycles
    jp main                                                           ; 0001: c3 1d 00    ... 10 cycles

    db 0, 0, 0, 0                                                     ; 0004: 00 00 00... ...

; $08 referenced 1 time by $4b
error:
    ex (sp),hl                                                        ; 0008: e3          .   19 cycles
    ld a,(hl)                                                         ; 0009: 7e          ~   7 cycles
    inc hl                                                            ; 000a: 23          #   6 cycles
    ex (sp),hl                                                        ; 000b: e3          .   19 cycles
    jr report                                                         ; 000c: 18 0a       ..  12 cycles

    db 0, 0                                                           ; 000e: 00 00       ..

; $10 referenced 1 time by $22
rst_10:
    out (ula_port),a                                                  ; 0010: d3 fe       ..  11 cycles
    ret                                                               ; 0012: c9          .   10 cycles

    db 0, 0, 0, 0, 0                                                  ; 0013: 00 00 00... ...

; $18 referenced 1 time by $0c
report:
    ld (last_error),a                                                 ; 0018: 32 57 00    2W. 13 cycles
    jr $-35                                                           ; 001b: 18 db       ..  12 cycles

; $1d referenced 2 times by $01, $fff9[2]
main:
    ld sp,$ff00                                                       ; 001d: 31 00 ff    1.. 10 cycles
    ld a,$2a                                                          ; 0020: 3e 2a       >*  7 cycles
    rst $10                                                           ; 0022: d7          .   11 cycles
    ld b,+(count+1)*2                                                 ; 0023: 06 08       ..  7 cycles
; $25 referenced 1 time by $25
loop_c0025:
    djnz loop_c0025                                                   ; 0025: 10 fe       ..  8/13 cycles
    in a,(ula_port)                                                   ; 0027: db fe       ..  11 cycles
    ld ix,variables                                                   ; 0029: dd 21 59... .!Y 14 cycles
    ld a,(ix+count)                                                   ; 002d: dd 7e 03    .~. 19 cycles
    ld (ix-1),a                                                       ; 0030: dd 77 ff    .w. 19 cycles
    ld hl,routine_source                                              ; 0033: 21 50 00    !P. 10 cycles
    ld de,copy_to                                                     ; 0036: 11 00 80    ... 10 cycles
    ld bc,routine_end - routine_source                                ; 0039: 01 07 00    ... 10 cycles
    ldir                                                              ; 003c: ed b0       ..  16/21 cycles
    call routine                                                      ; 003e: cd 00 80    ... 17 cycles
    ld hl,done                                                        ; 0041: 21 4b 00    !K. 10 cycles
    push hl                                                           ; 0044: e5          .   11 cycles
    ld ix,finish                                                      ; 0045: dd 21 4d... .!M 14 cycles
    jp (ix)                                                           ; 0049: dd e9       ..  8 cycles

done:
    rst $08                                                           ; 004b: cf          .   11 cycles
    db 5                                                              ; 004c: 05          .              ; error number

; $4d referenced 1 time by $4e
finish:
    halt                                                              ; 004d: 76          v   4 cycles
    jr finish                                                         ; 004e: 18 fd       ..  12 cycles

routine_source:

; Move 1: $50 to $8000 for length 7
    disp $8000
; $50 referenced 2 times by $3e, $8005[1]
routine:
    ld a,(ix+0)                                                       ; 0050: dd 7e 00    .~. 19 cycles     :8000[1]
    inc a                                                             ; 0053: 3c          <   4 cycles      :8003[1]
    ret nz                                                            ; 0054: c0          .   5/11 cycles   :8004[1]
    jr routine                                                        ; 0055: 18 f9       ..  12 cycles     :8005[1]

    ent

last_error:
routine_end:
; $57 referenced 1 time by $18
    db 0, 0                                                           ; 0057: 00 00       ..
variables:
    db 1, 2, 3, 4                                                     ; 0059: 01 02 03... ...
top_source:

; Move 2: $5d to $fff8 for length 8
    disp $fff8
; $5d referenced 1 time by $1b
top:
    nop                                                               ; 005d: 00          .   4 cycles      :fff8[2]
    jr nz,$+36                                                        ; 005e: 20 22        "  7/12 cycles   :fff9[2]
    ld a,1                                                            ; 0060: 3e 01       >.  7 cycles      :fffb[2]
    or a                                                              ; 0062: b7          .   4 cycles      :fffd[2]
last:
    ret nz                                                            ; 0063: c0          .   5/11 cycles   :fffe[2]
    ret                                                               ; 0064: c9          .   10 cycles     :ffff[2]

    ent

pydis_end:

    assert ((count+1)*2) == $08
    assert (done) == $4b
    assert (finish) == $4d
    assert (routine_end - routine_source) == $07
    assert (routine_source) == $50
    assert (variables) == $59

; Label references by decreasing frequency:
;     main:          2
;     routine:       2
;     error:         1
;     finish:        1
;     last_error:    1
;     loop_c0025:    1
;     report:        1
;     routine_end:   1
;     rst_10:        1
;     top:           1

; Automatically generated labels:
;     loop_c0025
;     rst_10

; Stats:
;
;     Total size (Code + Data) = 101 bytes
;     Code                     = 83 bytes (82%)
;     Data                     = 18 bytes (18%)
;
;     Number of instructions   = 42
;     Number of data bytes     = 18 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

