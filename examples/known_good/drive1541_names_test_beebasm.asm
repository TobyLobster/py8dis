; Constants
job_bump    = &c0
job_execute = &e0
job_read    = &80

; Memory locations

; Zero page (&0000-&00ff)
jobs = &0000
hdrs = &0006
vnmi = &0065

; Buffer 0 (&0300-&03ff)
buffer_0 = &0300

; Buffer 1 (&0400-&04ff)
buffer_1 = &0400

; VIA 1 (serial bus) (&1800-&180f)
pb  = &1800

; VIA 2 (disk controller) (&1c00-&1c0f)
dskcnt  = &1c00
data2   = &1c01

; DOS ROM (&c000-&ffe5)
idle    = &ebe7
sync    = &f556
gcrbin  = &f8e0
errr    = &f969

    org &0500

.pydis_start
.drive_code
    sei                                                               ; 0500: 78          .
    lda dskcnt                                                        ; 0501: ad 00 1c    ...
    ora #8                                                            ; 0504: 09 08       ..
    sta dskcnt                                                        ; 0506: 8d 00 1c    ...

    ; Job 0: read track 18, sector 1 into buffer 0 ($0300)
    lda #&12                                                          ; 0509: a9 12       ..
    sta hdrs                                                          ; 050b: 85 06       ..
    ldx #1                                                            ; 050d: a2 01       ..
    stx hdrs+1                                                        ; 050f: 86 07       ..
    lda #job_read                                                     ; 0511: a9 80       ..
    sta jobs                                                          ; 0513: 85 00       ..

; &0515 referenced 1 time by &0517
.loop_c0515
    lda jobs                                                          ; 0515: a5 00       ..
    bmi loop_c0515                                                    ; 0517: 30 fc       0.

    ; Job 3: move the head to track 18, then run the code in buffer 3 (job_3_code)
    ldy #&12                                                          ; 0519: a0 12       ..
    sty hdrs+6                                                        ; 051b: 84 0c       ..
    lda #job_execute                                                  ; 051d: a9 e0       ..
    sta jobs+3                                                        ; 051f: 85 03       ..

; &0521 referenced 1 time by &0523
.loop_c0521
    lda jobs+3                                                        ; 0521: a5 03       ..
    bmi loop_c0521                                                    ; 0523: 30 fc       0.

    ; Job 1: move the head to track 1 (bump)
    lda #job_bump                                                     ; 0525: a9 c0       ..
    sta jobs+1                                                        ; 0527: 85 01       ..

    ; Copy 69 bytes of memory from buffer_0+1 to buffer_0+70
    ldy #&45 ; 'e'                                                    ; 0529: a0 45       .e
; &052b referenced 1 time by &0532
.loop_c052b
    lda (buffer_0+1) - 1,y                                            ; 052b: b9 00 03    ...
    sta (buffer_0+70) - 1,y                                           ; 052e: 99 45 03    .e.
    dey                                                               ; 0531: 88          .
    bne loop_c052b                                                    ; 0532: d0 f7       P.

    ; Set the NMI vector to nmi_handler
    lda #<nmi_handler                                                 ; 0534: a9 45       .e
    sta vnmi                                                          ; 0536: 85 65       ..
    lda #>nmi_handler                                                 ; 0538: a9 05       ..
    sta vnmi+1                                                        ; 053a: 85 66       ..

    lda #8                                                            ; 053c: a9 08       ..
    sta pb                                                            ; 053e: 8d 00 18    ...
    cli                                                               ; 0541: 58          x
    jmp idle                                                          ; 0542: 4c e7 eb    l.. ; The DOS's main loop, waiting for a command (and running the jobs)

.nmi_handler
    rti                                                               ; 0545: 40          @

    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 0546: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 055a: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 056e: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 0582: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 0596: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 05aa: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 05be: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 05d2: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   ; 05e6: 00 00 00... ...
    equb 0, 0, 0, 0, 0, 0                                             ; 05fa: 00 00 00... ...

.job_3_code
    jsr sync                                                          ; 0600: 20 56 f5     v. ; Wait for a sync mark (20 ms at most)
; &0603 referenced 1 time by &0603
.loop_c0603
    bvc loop_c0603                                                    ; 0603: 50 fe       p.
    clv                                                               ; 0605: b8          .
    lda data2                                                         ; 0606: ad 01 1c    ...
    sta buffer_1                                                      ; 0609: 8d 00 04    ...
    jsr gcrbin                                                        ; 060c: 20 e0 f8     .. ; Convert the GCR data read into the buffer at BUFPNT to binary
    lda #1                                                            ; 060f: a9 01       .. ; A=result (1 for OK)
    jmp errr                                                          ; 0611: 4c 69 f9    l.. ; End the job, with its result (A) in the job queue

.pydis_end

    assert &0300 == (buffer_0+1) - 1
    assert &0345 == (buffer_0+70) - 1
    assert &45 == <nmi_handler
    assert &05 == >nmi_handler

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     dskcnt:       2
;     jobs:         2
;     buffer_0:     1
;     buffer_1:     1
;     data2:        1
;     errr:         1
;     gcrbin:       1
;     hdrs:         1
;     idle:         1
;     loop_c0515:   1
;     loop_c0521:   1
;     loop_c052b:   1
;     loop_c0603:   1
;     pb:           1
;     sync:         1
;     vnmi:         1

; Automatically generated labels:
;     loop_c0515
;     loop_c0521
;     loop_c052b
;     loop_c0603

; Stats:
;
;     Total size (Code + Data) = 276 bytes
;     Code                     = 90 bytes (33%)
;     Data                     = 186 bytes (67%)
;
;     Number of instructions   = 42
;     Number of data bytes     = 186 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

