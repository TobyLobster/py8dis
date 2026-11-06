; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Memory locations

; OS workspace ($0200-$0279)
NDX equ $020d
RVS equ $020e
CINV equ $0219

; Screen memory ($8000-$83e7)
screen_memory   equ $8000

; BASIC ROM ($c000-$dfff)
STROUT  equ $ca27
LINPRT  equ $dc9f

; Screen editor ROM ($e000-$e7ff)
KEY equ $e685

; PIA 1 ($e810-$e813)
PIAL equ $e810
PIAK equ $e812

; Kernal entry points ($ffc0-$fff9)
CLRCHN  equ $ffcc
CHROUT  equ $ffd2
STOP    equ $ffe1
GETIN   equ $ffe4

; The PRG file's header: the address to load it at
    org $03ff
    da $0401

    org $0401

; 10 SYS1056
pydis_start
basic_line_10
    da basic_end                                                      ; 0401: 0b 04       ..
    da 10                                                             ; 0403: 0a 00       ..
    dfb $9e                                                           ; 0405: 9e          .
    dfb $31, $30, $35, $36 ; petscii "1056"                           ; 0406: 31 30 35... 105
    dfb 0                                                             ; 040a: 00          .
basic_end
    da 0                                                              ; 040b: 00 00       ..
    dfb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0       ; 040d: 00 00 00... ...

sys_entry
    lda #$93                                                          ; 0420: a9 93       .. ; A=character to output
    jsr CHROUT                                                        ; 0422: 20 d2 ff     R. ; Output $93 (clear screen)
    lda #<l046d                                                       ; 0425: a9 6d       .. ; A=string address (low byte)
    ldy #>l046d                                                       ; 0427: a0 04       .. ; Y=string address (high byte)
    jsr STROUT                                                        ; 0429: 20 27 ca     'J ; Print the zero-terminated string at A/Y
    lda #4                                                            ; 042c: a9 04       .. ; A=number to print (high byte)
    ldx #$d2 ; 'R'                                                    ; 042e: a2 d2       .R ; X=number to print (low byte)
    jsr LINPRT                                                        ; 0430: 20 9f dc     .. ; Print the 16-bit number in A/X
    sei                                                               ; 0433: 78          .

    ; Set the IRQ vector to irq_handler
    lda #<irq_handler                                                 ; 0434: a9 67       ..
    sta CINV                                                          ; 0436: 8d 19 02    ...
    lda #>irq_handler                                                 ; 0439: a9 04       ..
    sta CINV+1                                                        ; 043b: 8d 1a 02    ...

    cli                                                               ; 043e: 58          x
    lda #1                                                            ; 043f: a9 01       ..
    sta RVS                                                           ; 0441: 8d 0e 02    ...
    lda #$61                                                          ; 0444: a9 61       ..
    sta screen_memory                                                 ; 0446: 8d 00 80    ...
    lda #0                                                            ; 0449: a9 00       ..
    sta NDX                                                           ; 044b: 8d 0d 02    ...
; $044e referenced 1 time by $0456
loop_c044e
    jsr STOP                                                          ; 044e: 20 e1 ff     .. ; Check the STOP key (Z set if it's pressed)
    beq c045b                                                         ; 0451: f0 08       ..
    jsr GETIN                                                         ; 0453: 20 e4 ff     .. ; Get a character from the keyboard buffer (0 if there's none)
    beq loop_c044e                                                    ; 0456: f0 f6       ..
    jsr CHROUT                                                        ; 0458: 20 d2 ff     R. ; Output a character
; $045b referenced 1 time by $0451
c045b
    jsr CLRCHN                                                        ; 045b: 20 cc ff     L. ; Restore the default input and output (keyboard and screen)
    lda #9                                                            ; 045e: a9 09       ..
    sta PIAL                                                          ; 0460: 8d 10 e8    ...
    lda PIAK                                                          ; 0463: ad 12 e8    ...
    rts                                                               ; 0466: 60          .

irq_handler
    inc screen_memory+39                                              ; 0467: ee 27 80    .'.
    jmp KEY                                                           ; 046a: 4c 85 e6    l.. ; The Kernal's IRQ handler (updates the clock, flashes the cursor and scans the keyboard, then returns from the interrupt)

l046d
    dfb $48, $45, $4c, $4c, $4f, $2c, $20, $50 ; petscii "hello, p"   ; 046d: 48 45 4c... hel
    dfb $45, $54, $0d, 0 ; petscii "et", $0d, $00                     ; 0475: 45 54 0d... et.
pydis_end

    err irq_handler & $ff - $67
    err l046d & $ff - $6d
    err irq_handler & $ffff / $0100 - $04
    err l046d & $ffff / $0100 - $04
    err basic_end - $040b

; Label references by decreasing frequency:
;     CHROUT:          2
;     CINV:            1
;     CLRCHN:          1
;     GETIN:           1
;     KEY:             1
;     LINPRT:          1
;     NDX:             1
;     PIAK:            1
;     PIAL:            1
;     RVS:             1
;     STOP:            1
;     STROUT:          1
;     c045b:           1
;     loop_c044e:      1
;     screen_memory:   1

; Automatically generated labels:
;     c045b
;     l046d
;     loop_c044e

; Stats:
;
;     Total size (Code + Data) = 120 bytes
;     Code                     = 77 bytes (64%)
;     Data                     = 43 bytes (36%)
;
;     Number of instructions   = 32
;     Number of data bytes     = 21 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 16 bytes
;     Number of strings        = 2
