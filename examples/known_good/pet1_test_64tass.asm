; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; Memory locations

; OS workspace ($0200-$0279)
NDX = $020d
RVS = $020e
CINV = $0219

; Screen memory ($8000-$83e7)
screen_memory   = $8000

; BASIC ROM ($c000-$dfff)
STROUT  = $ca27
LINPRT  = $dc9f

; Screen editor ROM ($e000-$e7ff)
KEY = $e685

; PIA 1 ($e810-$e813)
PIAL = $e810
PIAK = $e812

; Kernal entry points ($ffc0-$fff9)
CLRCHN  = $ffcc
CHROUT  = $ffd2
STOP    = $ffe1
GETIN   = $ffe4

; The PRG file's header: the address to load it at
    * = $03ff
    .word $0401

    * = $0401

; 10 SYS1056
pydis_start
basic_line_10
    .word basic_end                                                   ; 0401: 0b 04       ..
    .word 10                                                          ; 0403: 0a 00       ..
    .byte $9e                                                         ; 0405: 9e          .
    .text "1056"                                                      ; 0406: 31 30 35... 105
    .byte 0                                                           ; 040a: 00          .
basic_end
    .word 0                                                           ; 040b: 00 00       ..
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0     ; 040d: 00 00 00... ...

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
    .text "hello, pet", $0d, 0                                        ; 046d: 48 45 4c... hel
pydis_end

.cerror (<irq_handler) != $67, "Assertion failed: <irq_handler == $67"
.cerror (<l046d) != $6d, "Assertion failed: <l046d == $6d"
.cerror (>irq_handler) != $04, "Assertion failed: >irq_handler == $04"
.cerror (>l046d) != $04, "Assertion failed: >l046d == $04"
.cerror (basic_end) != $040b, "Assertion failed: basic_end == $040b"

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

