; Constants
job_read    = &80

; Memory locations

; Vectors (&0300-&0333)
l0300   = &0300
l0301   = &0301

; 1541 drive
job_queue   = &0000

; The PRG file's header: the address to load it at
    org &07ff
    equw &0801

    org &0801

; 10 SYS2061
.pydis_start
.basic_line_10
    equw basic_end                                                    ; 0801: 0b 08       ..
    equw 10                                                           ; 0803: 0a 00       ..
    equb &9e                                                          ; 0805: 9e          .
    equb &32, &30, &36, &31 ; petscii "2061"                          ; 0806: 32 30 36... 206
    equb 0                                                            ; 080a: 00          .
.basic_end
    equw 0                                                            ; 080b: 00 00       ..

.sys_entry
    rts                                                               ; 080d: 60          .


; Move 1: &080e to &0310 for length 15
    org &0310
    lda #&80                                                          ; 080e: a9 80       ..  :0310[1]
    sta job_queue+5                                                   ; 0810: 85 05       ..  :0312[1]

    ; Job 1: read the job's track and sector into buffer 1 ($0400)
    lda #job_read                                                     ; 0812: a9 80       ..  :0314[1]
    sta job_queue+1                                                   ; 0814: 85 01       ..  :0316[1]   ; Set the memory configuration to RAM only ($80)

    lda l0300                                                         ; 0816: ad 00 03    ... :0318[1]
    sta l0301                                                         ; 0819: 8d 01 03    ... :031b[1]
    rts                                                               ; 081c: 60          .   :031e[1]


    ; Copy the newly assembled block of code back to its proper place in the binary
    ; file.
    ; (Note the parameter order: 'copyblock <start>,<end>,<dest>')
    copyblock &0310, *, &080e

    ; Clear the area of memory we just temporarily used to assemble the new block,
    ; allowing us to assemble there again if needed
    clear &0310, &031f

    ; Set the program counter to the next position in the binary file.
    org &080e + (* - &0310)

.pydis_end

    assert &080b == basic_end

save pydis_start - 2, pydis_end

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

