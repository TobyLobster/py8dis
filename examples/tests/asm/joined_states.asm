; What's known at a label, from the ways into it (November 2026), for
; joined_states (see its control file), which shows the CPU state after each
; instruction. Assemble with:
;
;   acme -o ../orig/joined_states.orig joined_states.asm
;
; (It isn't meant to do anything useful when run.)

    * = $2000

start
    jsr both_ways
    jsr guard_before_label
    jsr search_loop
    jsr via_jmp
    jsr subroutine
    rts

; 1. Both ways into 'joined' load Y with 5, so Y (and then A) is 5 there
both_ways
    lda $70
    beq one
    ldy #5
    bne joined              ; ALWAYS branch (Y isn't 0)
one
    ldy #5
joined
    tya                     ; A=5
    rts

; 2. The guard is before the label: X is less than 3 at 'ok', so the jump
;    table there has three entries (X is 0, 2 or 4 after ASL)
guard_before_label
    lda $71
    cmp #3
    bcc ok
    rts
ok
    asl
    tax
    lda table1+1,x
    pha
    lda table1,x
    pha
    rts

; 3. A search loop: X goes from 0 to 3 round the loop, so it's 0 to 3 at
;    'found', and the jump table there has four entries
search_loop
    lda $72
    ldx #0
loop
    cmp keys,x
    beq found
    inx
    cpx #4
    bne loop
    rts
found
    txa
    asl
    tax
    lda table2+1,x
    pha
    lda table2,x
    pha
    rts

; 4. A JMP goes to 'jumped_to', so nothing is known there (code could come
;    to it from elsewhere through the same address)
via_jmp
    ldy #6
    jmp jumped_to
jumped_to
    tya
    rts

; 5. Nothing is known at the start of a subroutine (it could be called from
;    code that isn't seen, e.g. through a vector), even though the only JSR
;    to it here has Y=7
subroutine
    ldy #7
    jsr sub
    rts
sub
    tya
    rts

keys
    !byte $41, $42, $43, $44
table1
    !word routine1a - 1, routine1b - 1, routine1c - 1
table2
    !word routine2a - 1, routine2b - 1, routine2c - 1, routine2d - 1

routine1a
    lda #$1a
    rts
routine1b
    lda #$1b
    rts
routine1c
    lda #$1c
    rts
routine2a
    lda #$2a
    rts
routine2b
    lda #$2b
    rts
routine2c
    lda #$2c
    rts
routine2d
    lda #$2d
    rts
