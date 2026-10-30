; Constants
ula_port    equ $fe

; Memory locations

; ROM ($00-$3fff)
cls         equ $0d6b
chan_open   equ $1601
pr_string   equ $203c
plot_sub    equ $22e5
print_fp    equ $2de3

; Screen ($4000-$57ff)
screen  equ $4000

; Attributes ($5800-$5aff)
attributes  equ $5800

; System variables ($5c00-$5cb5)
last_k  equ $5c08
err_nr  equ $5c3a
flags   equ $5c3b

    org $8000

pydis_start:
start:
    call cls                                                          ; 8000: cd 6b 0d    .k. ; Clear the screen
    ld a,2                                                            ; 8003: 3e 02       >.
    call chan_open                                                    ; 8005: cd 01 16    ... ; Open a channel
    ld a,$16                                                          ; 8008: 3e 16       >.
    rst $10                                                           ; 800a: d7          .  ; Print $16 (AT)
    ld a,$0a                                                          ; 800b: 3e 0a       >.
    rst $10                                                           ; 800d: d7          .  ; Print 10 (AT's line)
    ld a,5                                                            ; 800e: 3e 05       >.
    rst $10                                                           ; 8010: d7          .  ; Print 5 (AT's column)
    ld de,message                                                     ; 8011: 11 54 80    .T.
    ld bc,message_end - message                                       ; 8014: 01 06 00    ...
    call pr_string                                                    ; 8017: cd 3c 20    .< ; Print a string
    rst $28                                                           ; 801a: ef          .
    db $a3                                                            ; 801b: a3          .  ; stk-pi/2
    db $34                                                            ; 801c: 34          4  ; stk-data
    db $40, $b0, 0, 4                                                 ; 801d: 40 b0 00... @.. ; 4
    db 4                                                              ; 8021: 04          .  ; multiply
    db $38                                                            ; 8022: 38          8  ; end-calc

    call print_fp                                                     ; 8023: cd e3 2d    ..- ; Print the number on the calculator stack
    ld a,1                                                            ; 8026: 3e 01       >.
    out (ula_port),a                                                  ; 8028: d3 fe       .. ; Border blue
; $802a referenced 1 time by $802f
loop_c802a:
    ld a,$7f                                                          ; 802a: 3e 7f       >.
    in a,(ula_port)                                                   ; 802c: db fe       .. ; Read the keyboard (SPACE-B)
    rra                                                               ; 802e: 1f          .
    jr c,loop_c802a                                                   ; 802f: 38 f9       8.
    xor a                                                             ; 8031: af          .
    ld (last_k),a                                                     ; 8032: 32 08 5c    2.\
    res 5,(iy+flags - err_nr)                                         ; 8035: fd cb 01... ...
    ld a,$38                                                          ; 8039: 3e 38       >8
    ld (attributes),a                                                 ; 803b: 32 00 58    2.X
    ld a,$ff                                                          ; 803e: 3e ff       >.
    ld (screen),a                                                     ; 8040: 32 00 40    2.@
    ld bc,$1020                                                       ; 8043: 01 20 10    . .
    call plot_sub                                                     ; 8046: cd e5 22    .." ; Plot a pixel
    ld hl,$5c78                                                       ; 8049: 21 78 5c    !x\
    ld a,(hl)                                                         ; 804c: 7e          ~
    add a,$32                                                         ; 804d: c6 32       .2
; $804f referenced 1 time by $8050
loop_c804f:
    cp (hl)                                                           ; 804f: be          .
    jr nz,loop_c804f                                                  ; 8050: 20 fd        .
    rst $08                                                           ; 8052: cf          .
    db 8                                                              ; 8053: 08          .  ; Report 9 STOP statement
message:
    db "Hello"                                                        ; 8054: 48 65 6c... Hel
    db $0d                                                            ; 8059: 0d          .
message_end:
pydis_end:

; ASSERT ((flags - err_nr) == $01)
; ASSERT ((message) == $8054)
; ASSERT ((message_end - message) == $06)

; Label references by decreasing frequency:
;     attributes:   1
;     chan_open:    1
;     cls:          1
;     last_k:       1
;     loop_c802a:   1
;     loop_c804f:   1
;     plot_sub:     1
;     pr_string:    1
;     print_fp:     1
;     screen:       1

; Automatically generated labels:
;     loop_c802a
;     loop_c804f

; Stats:
;
;     Total size (Code + Data) = 90 bytes
;     Code                     = 75 bytes (83%)
;     Data                     = 15 bytes (17%)
;
;     Number of instructions   = 35
;     Number of data bytes     = 10 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 5 bytes
;     Number of strings        = 1

