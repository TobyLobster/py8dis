; An Apple II+ and IIe program for python/apple2_test.py (with
; apple.apple2()) and python/apple2e_names_test.py (with model="iie" and
; names="descriptive"): calls to the Monitor's routines, printing with COUT
; (a message, characters, and a DOS command after a Ctrl-D), the zero page,
; vectors set to handlers, soft switches, the language card, the IIe's
; switches, AUXMOVE and status switches, and the Disk II, indexed by the
; slot. Assemble with:
;
;   acme -o ../orig/apple2_test.orig apple2_test.asm
;
; (It isn't meant to do anything useful when run.)

; The Monitor's zero page and routines
ch      = $24
cv      = $25
invflg  = $32
cswl    = $36
cswh    = $37
a1l     = $3c
a2l     = $3e
a4l     = $42
in      = $0200
softev  = $03f2
irqloc  = $03fe
plot    = $f800
setcol  = $f864
prbl2   = $f94a
pread   = $fb1e
setgr   = $fb40
tabv    = $fb5b
setpwrc = $fb6f
home    = $fc58
wait    = $fca8
rdkey   = $fd0c
getln   = $fd6a
crout   = $fd8e
prbyte  = $fdda
cout    = $fded
cout1   = $fdf0
outport = $fe95
setvid  = $fe93
setnorm = $fe84
bell    = $ff3a
iorts   = $ff58
monz    = $ff69

; The soft switches, and the IIe's AUXMOVE
kbd      = $c000
kbdstrb  = $c010
spkr     = $c030
txtclr   = $c050
hires    = $c057
butn0    = $c061
rdvblbar = $c019
auxmove  = $c311
lcbank2  = $c083

* = $0803

start
    jsr home

    ; A message
    ldx #0
print_message
    lda message,x
    beq print_characters
    jsr cout
    inx
    bne print_message

    ; Characters, and a new line
print_characters
    lda #'H' | $80
    jsr cout
    lda #'I' | $80
    jsr cout
    lda #$8d
    jsr cout
    jsr crout

    ; A DOS command: Ctrl-D, the command and a CR
    lda #$84
    jsr cout
    lda #'P' | $80
    jsr cout
    lda #'R' | $80
    jsr cout
    lda #'#' | $80
    jsr cout
    lda #'0' | $80
    jsr cout
    lda #$8d
    jsr cout

    ; Other routines
    lda #$12
    jsr prbyte
    ldx #5
    jsr prbl2
    lda #10
    jsr tabv
    lda #$40
    jsr wait
    lda #1
    jsr outport
    jsr setvid
    jsr bell
    jsr setgr
    lda #9
    jsr setcol
    lda #10
    ldy #5
    jsr plot
    ldx #0
    jsr pread
    sty $06

    ; Read a key and a line
    jsr rdkey
    cmp #'Y' | $80
    beq got_yes
    jsr getln
    stx $07
    lda in
got_yes

    ; The zero page
    lda #5
    sta ch
    sta cv
    lda #$3f
    sta invflg
    jsr setnorm

    ; Vectors: the reset vector, the output hook and the IRQ vector
    lda #<reset_handler
    sta softev
    lda #>reset_handler
    sta softev+1
    jsr setpwrc
    lda #<my_cout
    sta cswl
    lda #>my_cout
    sta cswh
    lda #<my_irq
    sta irqloc
    lda #>my_irq
    sta irqloc+1

    ; Soft switches
    bit txtclr
    bit hires
    lda spkr
wait_for_key
    lda kbd
    bpl wait_for_key
    sta kbdstrb
    lda butn0
    bmi button_pressed
button_pressed

    ; The IIe's vertical blank, and AUXMOVE
wait_for_vbl
    lda rdvblbar
    bpl wait_for_vbl
    lda #<$2000
    sta a1l
    lda #>$2000
    sta a1l+1
    lda #<$3fff
    sta a2l
    lda #>$3fff
    sta a2l+1
    lda #<$2000
    sta a4l
    lda #>$2000
    sta a4l+1
    sec
    jsr auxmove

    ; Wait for the vertical blank to start
wait_for_vbl_start
    lda rdvblbar
    bmi wait_for_vbl_start

    ; The language card: read and write RAM bank 2 (two reads), read the
    ; ROM, then read the ROM and write RAM bank 1 (two reads)
    lda lcbank2
    lda lcbank2
    lda $c082
    lda $c089
    lda $c089

    ; The IIe's 80 columns, and auxiliary memory
    sta $c00d
    sta $c001
    sta $c000
    sta $c005
    sta $c004

    ; The Disk II in slot 6: the motor on, drive 1, read mode, wait for a
    ; byte, then the motor off
    ldx #$60
    lda $c089,x
    lda $c08a,x
    lda $c08e,x
read_disk_byte
    lda $c08c,x
    bpl read_disk_byte
    lda $c088,x

    ; Find this code's address
    jsr iorts
    tsx
    lda $0100,x
    jmp monz

reset_handler
    jmp monz

my_cout
    jmp cout1

my_irq
    rti

message
    !xor $80 {
        !text "HELLO, WORLD"
    }
    !byte $8d, 0
