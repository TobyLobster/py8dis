; An Acorn Atom program (November 2026), for python/atom_test.py, which
; disassembles it with acorn.atom(): it writes with OSWRCH, OSASCI and
; OSCRLF (control codes and text), prints a string with the kernel's #F7D1
; and a message in a loop, calls kernel routines, sets the write character
; vector, uses the file calls, and reads the hardware and workspace.
; Assemble with:
;
;   acme -o ../orig/atom_test.orig atom_test.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 6502

OSSHUT = $ffcb
OSFIND = $ffce
OSBPUT = $ffd1
OSBGET = $ffd4
OSSAVE = $ffdd
OSLOAD = $ffe0
OSRDCH = $ffe3
OSECHO = $ffe6
OSASCI = $ffe9
OSCRLF = $ffed
OSWRCH = $fff4
OSCLI  = $fff7

    * = $2900

start
    lda #12                 ; clear the screen
    jsr OSWRCH
    lda #'H'                ; "HI", then a new line
    jsr OSWRCH
    lda #'I'
    jsr OSWRCH
    jsr OSCRLF
    lda #7                  ; bell
    jsr OSWRCH
    lda #14                 ; page mode on
    jsr OSWRCH
    lda #'A'
    jsr OSASCI
    lda #13                 ; a new line with OSASCI
    jsr OSASCI
    lda #13                 ; CR and LF with OSWRCH
    jsr OSWRCH
    lda #10
    jsr OSWRCH

    jsr $f7d1               ; print the string after the JSR
    !text "HELLO ATOM"
    nop                     ; (bit 7 set: carry on here)

    ldx #0                  ; print a message
print_loop
    lda message,x
    jsr OSWRCH
    inx
    cpx #message_end - message
    bne print_loop

    lda #$41                ; kernel routines
    jsr $f802
    jsr $f7fd
    jsr $fe66

    lda #<new_wrch          ; set the write character vector
    sta $0208
    lda #>new_wrch
    sta $0209
    lda #0                  ; set the low byte of the BRK vector
    sta $0202

    jsr OSRDCH              ; read a character
    sta $70
    jsr OSECHO
    sta $71
    sec                     ; open a file for input
    ldx #$80
    jsr OSFIND
    sta $72
    ldy $72                 ; read a byte from it
    jsr OSBGET
    sta $73
    lda #65                 ; write a byte
    ldy $72
    jsr OSBPUT
    ldy #0                  ; close all files
    jsr OSSHUT
    ldx #$84                ; load and save
    jsr OSLOAD
    ldx #$84
    jsr OSSAVE
    jsr OSCLI

    lda $b001               ; the hardware and workspace
    sta $b801
    lda $b002
    ldx $e0
    lda $12
    rts

new_wrch
    jmp $fe52

message
    !text "ATOM"
message_end
