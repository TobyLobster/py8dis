.cpu "6502i"

; Text encodings (for '.text' and character literals)
    .enc "petscii"
    .cdef " @", $20
    .cdef "AZ", $c1
    .cdef "[[", $5b
    .cdef "]]", $5d
    .cdef "az", $41

; Constants
colour_black    = 0
device_disk_8   = 8
job_execute     = $e0
job_ok          = 1     ; OK
job_read        = $80

; Memory locations

; 6510 I/O port ($0000-$0001)
cpu_port = $0001

; VIC-II ($d000-$d3ff)
vic_border_colour   = $d020

; Kernal entry points ($ff81-$fff9)
setlfs  = $ffba
setnam  = $ffbd
open    = $ffc0
chkout  = $ffc9
clrchn  = $ffcc
chrout  = $ffd2

; 1541 drive
job_queue           = $0000
job_track_sector    = $0006
buffer_0            = $0300
buffer_1            = $0400
via1_serial_bus     = $1800
via2_disk_control   = $1c00
via2_disk_data      = $1c01
dos_idle_loop       = $ebe7
wait_for_sync       = $f556
end_job             = $f969

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
    lda #$37 ; '7'                                                    ; 080d: a9 37       .7
    sta cpu_port                                                      ; 080f: 85 01       ..
    lda #colour_black                                                 ; 0811: a9 00       ..
    sta vic_border_colour                                             ; 0813: 8d 20 d0    . P
    lda #$0f                                                          ; 0816: a9 0f       ..             ; A=logical file number
    ldx #device_disk_8                                                ; 0818: a2 08       ..             ; X=device number
    ldy #$0f                                                          ; 081a: a0 0f       ..             ; Y=secondary address
    jsr setlfs                                                        ; 081c: 20 ba ff     ..            ; Set logical file 15 to device 8 (disk drive), secondary address 15
    lda #0                                                            ; 081f: a9 00       ..             ; A=filename length
    jsr setnam                                                        ; 0821: 20 bd ff     ..            ; Set no filename
    jsr open                                                          ; 0824: 20 c0 ff     ..            ; Open a logical file (set up with SETLFS and SETNAM)
    ldx #$0f                                                          ; 0827: a2 0f       ..             ; X=logical file number
    jsr chkout                                                        ; 0829: 20 c9 ff     I.            ; Open a channel for output
    ldy #0                                                            ; 082c: a0 00       ..
; $082e referenced 1 time by $0835
loop_c082e
    lda c083b,y                                                       ; 082e: b9 3b 08    .;.            ; A=character to output
    jsr chrout                                                        ; 0831: 20 d2 ff     R.            ; Output a character
    iny                                                               ; 0834: c8          H
    bne loop_c082e                                                    ; 0835: d0 f7       P.
    jsr clrchn                                                        ; 0837: 20 cc ff     L.            ; Restore the default input and output channels
    rts                                                               ; 083a: 60          .

; $083b referenced 1 time by $082e
c083b

; Move 1: $083b to $0500 for length 273
.logical $0500
drive_code
    sei                                                               ; 083b: 78          .   :0500[1]
    lda via2_disk_control                                             ; 083c: ad 00 1c    ... :0501[1]
    ora #8                                                            ; 083f: 09 08       ..  :0504[1]
    sta via2_disk_control                                             ; 0841: 8d 00 1c    ... :0506[1]   ; Turn the LED on

    ; Job 0: read track 18, sector 1 into buffer 0 ($0300)
    lda #$12                                                          ; 0844: a9 12       ..  :0509[1]
    sta job_track_sector                                              ; 0846: 85 06       ..  :050b[1]
    lda #1                                                            ; 0848: a9 01       ..  :050d[1]
    sta job_track_sector+1                                            ; 084a: 85 07       ..  :050f[1]
    lda #job_read                                                     ; 084c: a9 80       ..  :0511[1]
    sta job_queue                                                     ; 084e: 85 00       ..  :0513[1]

; $0850 referenced 1 time by $0517[1]
loop_c0515
    lda job_queue                                                     ; 0850: a5 00       ..  :0515[1]
    bmi loop_c0515                                                    ; 0852: 30 fc       0.  :0517[1]
    ; Copy 69 bytes of memory from buffer_0+1 to buffer_0+70
    ldx #$45 ; 'e'                                                    ; 0854: a2 45       .e  :0519[1]
; $0856 referenced 1 time by $0522[1]
loop_c051b
    lda (buffer_0+1) - 1,x                                            ; 0856: bd 00 03    ... :051b[1]
    sta (buffer_0+70) - 1,x                                           ; 0859: 9d 45 03    .e. :051e[1]
    dex                                                               ; 085c: ca          J   :0521[1]
    bne loop_c051b                                                    ; 085d: d0 f7       P.  :0522[1]

    ; Job 3: move the head to track 18, then run the code in buffer 3 (job_3_code)
    lda #$12                                                          ; 085f: a9 12       ..  :0524[1]
    sta job_track_sector+6                                            ; 0861: 85 0c       ..  :0526[1]
    lda #job_execute                                                  ; 0863: a9 e0       ..  :0528[1]
    sta job_queue+3                                                   ; 0865: 85 03       ..  :052a[1]

; $0867 referenced 1 time by $052e[1]
loop_c052c
    lda job_queue+3                                                   ; 0867: a5 03       ..  :052c[1]
    bmi loop_c052c                                                    ; 0869: 30 fc       0.  :052e[1]
    lda via1_serial_bus                                               ; 086b: ad 00 18    ... :0530[1]
    and #4                                                            ; 086e: 29 04       ).  :0533[1]   ; Test CLOCK IN
    cli                                                               ; 0870: 58          x   :0535[1]
    jmp dos_idle_loop                                                 ; 0871: 4c e7 eb    l.. :0536[1]   ; The DOS's main loop, waiting for a command (and running the jobs)

    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0874: 00 00 00... ... :0539[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0888: 00 00 00... ... :054d[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 089c: 00 00 00... ... :0561[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08b0: 00 00 00... ... :0575[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08c4: 00 00 00... ... :0589[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08d8: 00 00 00... ... :059d[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 08ec: 00 00 00... ... :05b1[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0900: 00 00 00... ... :05c5[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  ; 0914: 00 00 00... ... :05d9[1]
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0     ; 0928: 00 00 00... ... :05ed[1]

job_3_code
    jsr wait_for_sync                                                 ; 093b: 20 56 f5     v. :0600[1]   ; Wait for a sync mark (20 ms at most)
; $093e referenced 1 time by $0603[1]
loop_c0603
    bvc loop_c0603                                                    ; 093e: 50 fe       p.  :0603[1]
    clv                                                               ; 0940: b8          .   :0605[1]
    lda via2_disk_data                                                ; 0941: ad 01 1c    ... :0606[1]
    sta buffer_1                                                      ; 0944: 8d 00 04    ... :0609[1]
    lda #job_ok                                                       ; 0947: a9 01       ..  :060c[1]
    jmp end_job                                                       ; 0949: 4c 69 f9    l.. :060e[1]   ; End the job, with its result (A) in the job queue

.here

pydis_end

.cerror ((buffer_0+1) - 1) != $0300, "Assertion failed: (buffer_0+1) - 1 == $0300"
.cerror ((buffer_0+70) - 1) != $0345, "Assertion failed: (buffer_0+70) - 1 == $0345"
.cerror (basic_end) != $080b, "Assertion failed: basic_end == $080b"

; Label references by decreasing frequency:
;     job_queue:           2
;     via2_disk_control:   2
;     buffer_0:            1
;     buffer_1:            1
;     c083b:               1
;     chkout:              1
;     chrout:              1
;     clrchn:              1
;     cpu_port:            1
;     dos_idle_loop:       1
;     end_job:             1
;     job_track_sector:    1
;     loop_c0515:          1
;     loop_c051b:          1
;     loop_c052c:          1
;     loop_c0603:          1
;     loop_c082e:          1
;     open:                1
;     setlfs:              1
;     setnam:              1
;     via1_serial_bus:     1
;     via2_disk_data:      1
;     vic_border_colour:   1
;     wait_for_sync:       1

; Automatically generated labels:
;     c083b
;     loop_c0515
;     loop_c051b
;     loop_c052c
;     loop_c0603
;     loop_c082e

; Stats:
;
;     Total size (Code + Data) = 331 bytes
;     Code                     = 120 bytes (36%)
;     Data                     = 211 bytes (64%)
;
;     Number of instructions   = 54
;     Number of data bytes     = 201 bytes
;     Number of data words     = 6 bytes
;     Number of string bytes   = 4 bytes
;     Number of strings        = 1

