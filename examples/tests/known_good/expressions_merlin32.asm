; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Constants
a_      equ 1
b       equ 2
c       equ 3
k       equ 127
m       equ 15
p       equ 15
q       equ 48
r       equ 60
table   equ 4660
ten     equ 10
x_      equ 5

    org $2000

pydis_start
    dfb <{table + 1}                                                  ; 2000: 35          5
    dfb {table & $ffff} / $0100 + 1                                   ; 2001: 13          .
    dfb {255 - k} ! 128                                               ; 2002: 00          .
    dfb a_ + b + c                                                    ; 2003: 06          .
    dfb a_ + b + c                                                    ; 2004: 06          .
    dfb ten - {b - c}                                                 ; 2005: 0b          .
    dfb x_ * 2 + 1                                                    ; 2006: 0b          .
    dfb x_ * {2 + 1}                                                  ; 2007: 0f          .
    dfb {m ! $ffffffff} & $ff                                         ; 2008: f0          .
    dfb {p . q} & r                                                   ; 2009: 3c          <
    dfb p . {q & r}                                                   ; 200a: 3f          ?
    dfb table & $ff & $7f                                             ; 200b: 34          4
    dfb {p+1} * 2                                                     ; 200c: 20
    dfb >{table + $0100}                                              ; 200d: 13          .
    dfb p ! q ! r                                                     ; 200e: 03          .
    dfb p . {q ! r}                                                   ; 200f: 0f          .
    dfb {table / $0100} & $ff                                         ; 2010: 12          .
    dfb 1 * 8 + 1                                                     ; 2011: 09          .
    dfb x_ / 2                                                        ; 2012: 02          .
    da table - 1                                                      ; 2013: 33 12       3.
    dfb {m ! $ffffffff} & $ff                                         ; 2015: f0          .
    dfb {0 - k} & $ff                                                 ; 2016: 81          .
    da {table ! $ffffffff} & $ffff                                    ; 2017: cb ed       ..
pydis_end

    err 1 * 8 + 1 - $09
    err {table + 1} & $ff - $35
    err {table + $0100} & $ffff / $0100 - $13
    err a_ + b + c - $06
    err p ! q ! r - $03
    err p . {q ! r} - $0f
    err p . {q & r} - $3f
    err table & $ff & $7f - $34
    err table - 1 - $1233
    err ten - {b - c} - $0b
    err x_ * 2 + 1 - $0b
    err x_ * {2 + 1} - $0f
    err x_ / 2 - $02
    err {0 - k} & $ff - $81
    err {255 - k} ! 128 - $00
    err {m ! $ffffffff} & $ff - $f0
    err {p . q} & r - $3c
    err {p+1} * 2 - $20
    err {table ! $ffffffff} & $ffff - $edcb
    err {table & $ffff} / $0100 + 1 - $13
    err {table / $0100} & $ff - $12

; Stats:
;
;     Total size (Code + Data) = 25 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 25 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 21 bytes
;     Number of data words     = 4 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0
