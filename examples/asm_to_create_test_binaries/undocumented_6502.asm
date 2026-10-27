; Every undocumented 6502 opcode, for load(..., "6510") (see
; python/undocumented_6502.py). Assemble with:
;
;   acme -o ../orig/undocumented_6502.orig undocumented_6502.asm
;
; acme assembles 70 of the 105 from their mnemonics. The rest are other
; opcodes for the same instruction (e.g. ANC is $0b and $2b; JAM and the NOPs
; have many), which acme doesn't use, so they're given as bytes.

!cpu 6510

zp1   = $70
zp2   = $72
addr1 = $3000
addr2 = $3456

    * = $2000

start
    ; SLO, RLA, SRE, RRA, DCP, ISC: each in its seven addressing modes
    slo (zp1,x)
    slo zp1
    slo addr1
    slo (zp1),y
    slo zp1,x
    slo addr1,y
    slo addr1,x
    rla (zp1,x)
    rla zp1
    rla addr1
    rla (zp1),y
    rla zp1,x
    rla addr1,y
    rla addr1,x
    sre (zp1,x)
    sre zp1
    sre addr1
    sre (zp1),y
    sre zp1,x
    sre addr1,y
    sre addr1,x
    rra (zp1,x)
    rra zp1
    rra addr1
    rra (zp1),y
    rra zp1,x
    rra addr1,y
    rra addr1,x
    dcp (zp2,x)
    dcp zp2
    dcp addr2
    dcp (zp2),y
    dcp zp2,x
    dcp addr2,y
    dcp addr2,x
    isc (zp2,x)
    isc zp2
    isc addr2
    isc (zp2),y
    isc zp2,x
    isc addr2,y
    isc addr2,x

    ; SAX and LAX
    sax (zp1,x)
    sax zp1
    sax addr1
    sax zp1,y
    lax (zp2,x)
    lax zp2
    lax addr2
    lax (zp2),y
    lax zp2,y
    lax addr2,y

    ; Absolute addressing with a zero page address (as for documented
    ; instructions, this must be forced)
    slo+2 zp1
    lax+2 zp2,y
    nop+2 zp1,x

    ; The immediate ones, with known values to show the CPU state
    lda #$ff
    anc #$81
    !byte $2b, $7f          ; anc #$7f
    lda #$f3
    alr #$0f
    lda #$3c
    ldx #$0f
    sbx #$05
    arr #$12
    !byte $eb, $01          ; sbc #$01

    ; The NOPs
    !byte $1a               ; nop
    !byte $3a               ; nop
    !byte $5a               ; nop
    !byte $7a               ; nop
    !byte $da               ; nop
    !byte $fa               ; nop
    nop #$12                ; $80
    !byte $82, $12          ; nop #$12
    !byte $89, $12          ; nop #$12
    !byte $c2, $12          ; nop #$12
    !byte $e2, $12          ; nop #$12
    nop zp1                 ; $04
    !byte $44, zp1          ; nop zp1
    !byte $64, zp1          ; nop zp1
    nop zp1,x               ; $14
    !byte $34, zp1          ; nop zp1,x
    !byte $54, zp1          ; nop zp1,x
    !byte $74, zp1          ; nop zp1,x
    !byte $d4, zp1          ; nop zp1,x
    !byte $f4, zp1          ; nop zp1,x
    nop addr1               ; $0c
    nop addr1,x             ; $1c
    !byte $3c               ; nop addr1,x
    !word addr1
    !byte $5c               ; nop addr1,x
    !word addr1
    !byte $7c               ; nop addr1,x
    !word addr1
    !byte $dc               ; nop addr1,x
    !word addr1
    !byte $fc               ; nop addr1,x
    !word addr1

    ; The unstable ones
    ane #$12
    lxa #$12
    las addr1,y
    tas addr1,y
    sha (zp1),y
    sha addr1,y
    shx addr1,y
    shy addr1,x

    ; The JAMs, each skipped by a branch (so tracing continues past it)
    beq +
    jam                     ; $02
+   beq +
    !byte $12               ; jam
+   beq +
    !byte $22               ; jam
+   beq +
    !byte $32               ; jam
+   beq +
    !byte $42               ; jam
+   beq +
    !byte $52               ; jam
+   beq +
    !byte $62               ; jam
+   beq +
    !byte $72               ; jam
+   beq +
    !byte $92               ; jam
+   beq +
    !byte $b2               ; jam
+   beq +
    !byte $d2               ; jam
+   beq +
    !byte $f2               ; jam
+   rts
