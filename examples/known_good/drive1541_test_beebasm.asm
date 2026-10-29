; Constants
job_bump    = &c0
job_execute = &e0
job_read    = &80

; Memory locations

; Zero page (&0000-&00ff)
job_queue       = &0000
job_track_sector = &0006
nmi_vector      = &0065

; Buffer 0 (&0300-&03ff)
buffer_0 = &0300

; Buffer 1 (&0400-&04ff)
buffer_1 = &0400

; VIA 1 (serial bus) (&1800-&180f)
via1_serial_bus = &1800

; VIA 2 (disk controller) (&1c00-&1c0f)
via2_disk_control   = &1c00
via2_disk_data      = &1c01

; DOS ROM (&c000-&ffe5)
dos_idle_loop   = &ebe7
wait_for_sync   = &f556
gcr_to_binary   = &f8e0
end_job         = &f969

    org &0500

.pydis_start
.drive_code
    sei                                                               ; 0500: 78          .
    lda via2_disk_control                                             ; 0501: ad 00 1c    ...
    ora #8                                                            ; 0504: 09 08       ..
    sta via2_disk_control                                             ; 0506: 8d 00 1c    ...

    ; Job 0: read track 18, sector 1 into buffer 0 ($0300)
    lda #&12                                                          ; 0509: a9 12       ..
    sta job_track_sector                                              ; 050b: 85 06       ..
    ldx #1                                                            ; 050d: a2 01       ..
    stx job_track_sector+1                                            ; 050f: 86 07       ..
    lda #job_read                                                     ; 0511: a9 80       ..
    sta job_queue                                                     ; 0513: 85 00       ..

; &0515 referenced 1 time by &0517
.loop_c0515
    lda job_queue                                                     ; 0515: a5 00       ..
    bmi loop_c0515                                                    ; 0517: 30 fc       0.

    ; Job 3: move the head to track 18, then run the code in buffer 3 (job_3_code)
    ldy #&12                                                          ; 0519: a0 12       ..
    sty job_track_sector+6                                            ; 051b: 84 0c       ..
    lda #job_execute                                                  ; 051d: a9 e0       ..
    sta job_queue+3                                                   ; 051f: 85 03       ..

; &0521 referenced 1 time by &0523
.loop_c0521
    lda job_queue+3                                                   ; 0521: a5 03       ..
    bmi loop_c0521                                                    ; 0523: 30 fc       0.

    ; Job 1: move the head to track 1 (bump)
    lda #job_bump                                                     ; 0525: a9 c0       ..
    sta job_queue+1                                                   ; 0527: 85 01       ..

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
    sta nmi_vector                                                    ; 0536: 85 65       ..
    lda #>nmi_handler                                                 ; 0538: a9 05       ..
    sta nmi_vector+1                                                  ; 053a: 85 66       ..

    lda #8                                                            ; 053c: a9 08       ..
    sta via1_serial_bus                                               ; 053e: 8d 00 18    ...
    cli                                                               ; 0541: 58          x
    jmp dos_idle_loop                                                 ; 0542: 4c e7 eb    l.. ; The DOS's main loop, waiting for a command (and running the jobs)

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
    jsr wait_for_sync                                                 ; 0600: 20 56 f5     v. ; Wait for a sync mark (20 ms at most)
; &0603 referenced 1 time by &0603
.loop_c0603
    bvc loop_c0603                                                    ; 0603: 50 fe       p.
    clv                                                               ; 0605: b8          .
    lda via2_disk_data                                                ; 0606: ad 01 1c    ...
    sta buffer_1                                                      ; 0609: 8d 00 04    ...
    jsr gcr_to_binary                                                 ; 060c: 20 e0 f8     .. ; Convert the GCR data read into the buffer at BUFPNT to binary
    lda #1                                                            ; 060f: a9 01       .. ; A=result (1 for OK)
    jmp end_job                                                       ; 0611: 4c 69 f9    l.. ; End the job, with its result (A) in the job queue

.pydis_end

    assert &0300 == (buffer_0+1) - 1
    assert &0345 == (buffer_0+70) - 1
    assert &45 == <nmi_handler
    assert &05 == >nmi_handler

save pydis_start, pydis_end

; Label references by decreasing frequency:
;     job_queue:           2
;     via2_disk_control:   2
;     buffer_0:            1
;     buffer_1:            1
;     dos_idle_loop:       1
;     end_job:             1
;     gcr_to_binary:       1
;     job_track_sector:    1
;     loop_c0515:          1
;     loop_c0521:          1
;     loop_c052b:          1
;     loop_c0603:          1
;     nmi_vector:          1
;     via1_serial_bus:     1
;     via2_disk_data:      1
;     wait_for_sync:       1

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

