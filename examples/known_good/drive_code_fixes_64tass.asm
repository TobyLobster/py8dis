; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; Constants
job_read    = $80

; Memory locations

; Vectors ($0300-$0333)
l0300   = $0300
l0301   = $0301

; 1541 drive
job_queue   = $0000

; The PRG file's header: the address to load it at
    * = $07ff
    .word $0801

    * = $0801

; 10 SYS2061
pydis_start
basic_line_10
    .word basic_end                                                   ; 0801: 0b 08       ..
    .word 10                                                          ; 0803: 0a 00       ..
    .byte $9e                                                         ; 0805: 9e          .
    .text "2061"                                                      ; 0806: 32 30 36... 206
    .byte 0                                                           ; 080a: 00          .
basic_end
    .word 0                                                           ; 080b: 00 00       ..

sys_entry
    rts                                                               ; 080d: 60          .


; Move 1: $080e to $0310 for length 15
.logical $0310
    lda #$80                                                          ; 080e: a9 80       ..  :0310[1]
    sta job_queue+5                                                   ; 0810: 85 05       ..  :0312[1]

    ; Job 1: read the job's track and sector into buffer 1 ($0400)
    lda #job_read                                                     ; 0812: a9 80       ..  :0314[1]
    sta job_queue+1                                                   ; 0814: 85 01       ..  :0316[1]   ; Set the memory configuration to RAM only ($80)

    lda l0300                                                         ; 0816: ad 00 03    ... :0318[1]
    sta l0301                                                         ; 0819: 8d 01 03    ... :031b[1]
    rts                                                               ; 081c: 60          .   :031e[1]

.here

pydis_end

.cerror (basic_end) != $080b, "Assertion failed: basic_end == $080b"

; Label references by decreasing frequency:
;     l0300:   1
;     l0301:   1

; Automatically generated labels:
;     l0300
;     l0301

; Stats:
;
;     Total size (Code + Data) = 28 bytes
;     Code                     = 16 bytes (57%)
;     Data                     = 12 bytes (43%)
;
;     Number of instructions   = 8
;     Number of data bytes     = 2 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1

