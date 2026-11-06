; Assemble with Merlin 32, which writes the program to a file named after
; this one without its extension, in the same folder:
;     merlin32 this_file.asm

; Constants
job_read    equ $80

; Memory locations

; 1541 drive
job_queue   equ $00
l0300       equ $0300
l0301       equ $0301

; The PRG file's header: the address to load it at
    org $07ff
    da $0801

    org $0801

; 10 SYS2061
pydis_start
basic_line_10
    da basic_end                                                      ; 0801: 0b 08       ..
    da 10                                                             ; 0803: 0a 00       ..
    dfb $9e                                                           ; 0805: 9e          .
    dfb $32, $30, $36, $31 ; petscii "2061"                           ; 0806: 32 30 36... 206
    dfb 0                                                             ; 080a: 00          .
basic_end
    da 0                                                              ; 080b: 00 00       ..

sys_entry
    rts                                                               ; 080d: 60          .


; Move 1: $080e to $0310 for length 15
    org $0310
    lda #$80                                                          ; 080e: a9 80       ..  :0310[1]
    sta job_queue+5                                                   ; 0810: 85 05       ..  :0312[1]

    ; Job 1: read the job's track and sector into buffer 1 ($0400)
    lda #job_read                                                     ; 0812: a9 80       ..  :0314[1]
    sta job_queue+1                                                   ; 0814: 85 01       ..  :0316[1]   ; Set the memory configuration to RAM only ($80)

    lda l0300                                                         ; 0816: ad 00 03    ... :0318[1]
    sta l0301                                                         ; 0819: 8d 01 03    ... :031b[1]
    rts                                                               ; 081c: 60          .   :031e[1]

    org $081d

pydis_end

    err basic_end - $080b

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
