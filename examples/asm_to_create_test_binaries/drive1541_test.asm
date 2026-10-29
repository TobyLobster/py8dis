; Code for the 1541 disk drive, for python/drive1541_test.py: loaded at
; &0500 (buffer 2), as a program would send it with M-W and run it with M-E,
; with the code for an EXECUTE job in buffer 3 (&0600).
;
;   acme -f plain -o ../orig/drive1541_test.orig drive1541_test.asm
;   cp ../orig/drive1541_test.orig ../orig/drive1541_names_test.orig

jobs    = $00           ; the job queue
hdrs    = $06           ; each job's track and sector
vnmi    = $65           ; the NMI vector
pb      = $1800         ; VIA 1 port B: the serial bus
dskcnt  = $1c00         ; VIA 2 port B: the drive's controls
data2   = $1c01         ; VIA 2 port A: the data read from the disk
idle    = $ebe7         ; the DOS's main loop
sync    = $f556         ; wait for a sync mark
gcrbin  = $f8e0         ; convert GCR to binary
errr    = $f969         ; end a job

    * = $0500
    sei
    lda dskcnt          ; turn on the LED
    ora #$08
    sta dskcnt

    lda #18             ; read track 18, sector 1 into buffer 0
    sta hdrs
    ldx #1
    stx hdrs+1
    lda #$80
    sta jobs
wait_read
    lda jobs
    bmi wait_read

    ldy #18             ; run the code in buffer 3, on track 18
    sty hdrs+6
    lda #$e0
    sta jobs+3
wait_execute
    lda jobs+3
    bmi wait_execute

    lda #$c0            ; bump the head (job 1)
    sta jobs+1

    ldy #69             ; move &0301-&0345 up 69 bytes, from the top down
move_up
    lda $0300,y
    sta $0345,y
    dey
    bne move_up

    lda #<nmi           ; set the NMI vector
    sta vnmi
    lda #>nmi
    sta vnmi+1

    lda #$08            ; clock out on the serial bus
    sta pb
    cli
    jmp idle

nmi
    rti

    * = $0600
    ; The EXECUTE job's code, with the head on track 18
    jsr sync
wait_byte
    bvc wait_byte
    clv
    lda data2
    sta $0400
    jsr gcrbin
    lda #1              ; OK
    jmp errr
