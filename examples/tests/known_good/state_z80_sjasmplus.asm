; Assemble with sjasmplus, to a plain binary:
;     sjasmplus --nologo --raw=program.bin this_file.asm

    org $8000

pydis_start:
start:
    ld a,$7f                                                          ; 8000: 3e 7f       >.  A:7f BC:---- DE:---- HL:---- IX:---- IY:---- SP:---- ------
    inc a                                                             ; 8002: 3c          <   A:80 BC:---- DE:---- HL:---- IX:---- IY:---- SP:---- SzHPn-
    ld b,a                                                            ; 8003: 47          G   A:80 BC:80-- DE:---- HL:---- IX:---- IY:---- SP:---- SzHPn-
    add a,b                                                           ; 8004: 80          .   A:00 BC:80-- DE:---- HL:---- IX:---- IY:---- SP:---- sZhPnC
    adc a,$10                                                         ; 8005: ce 10       ..  A:11 BC:80-- DE:---- HL:---- IX:---- IY:---- SP:---- szhpnc
    sub $12                                                           ; 8007: d6 12       ..  A:ff BC:80-- DE:---- HL:---- IX:---- IY:---- SP:---- SzHpNC
    neg                                                               ; 8009: ed 44       .D  A:01 BC:80-- DE:---- HL:---- IX:---- IY:---- SP:---- szHpNC
    ld c,$99                                                          ; 800b: 0e 99       ..  A:01 BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- szHpNC
    ld a,c                                                            ; 800d: 79          y   A:99 BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- szHpNC
    add a,1                                                           ; 800e: c6 01       ..  A:9a BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- Szhpnc
    daa                                                               ; 8010: 27          '   A:00 BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZHPnC
    xor a                                                             ; 8011: af          .   A:00 BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZhPnc
    cpl                                                               ; 8012: 2f          /   A:ff BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZHPNc
    and $0f                                                           ; 8013: e6 0f       ..  A:0f BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- szHPnc
    or $30                                                            ; 8015: f6 30       .0  A:3f BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- szhPnc
    cp $3f                                                            ; 8017: fe 3f       .?  A:3f BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZhpNc
    scf                                                               ; 8019: 37          7   A:3f BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZhpnC
    ccf                                                               ; 801a: 3f          ?   A:3f BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZHpnc
    rlca                                                              ; 801b: 07          .   A:7e BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- sZhpnc
    sla a                                                             ; 801c: cb 27       .'  A:fc BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- SzhPnc
    bit 7,a                                                           ; 801e: cb 7f       ..  A:fc BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- SzHpnc
    set 0,a                                                           ; 8020: cb c7       ..  A:fd BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- SzHpnc
    res 1,a                                                           ; 8022: cb 8f       ..  A:fd BC:8099 DE:---- HL:---- IX:---- IY:---- SP:---- SzHpnc
    ld hl,$1234                                                       ; 8024: 21 34 12    !4. A:fd BC:8099 DE:---- HL:1234 IX:---- IY:---- SP:---- SzHpnc
    ld de,$1000                                                       ; 8027: 11 00 10    ... A:fd BC:8099 DE:1000 HL:1234 IX:---- IY:---- SP:---- SzHpnc
    add hl,de                                                         ; 802a: 19          .   A:fd BC:8099 DE:1000 HL:2234 IX:---- IY:---- SP:---- Szhpnc
    or a                                                              ; 802b: b7          .   A:fd BC:8099 DE:1000 HL:2234 IX:---- IY:---- SP:---- Szhpnc
    sbc hl,de                                                         ; 802c: ed 52       .R  A:fd BC:8099 DE:1000 HL:1234 IX:---- IY:---- SP:---- szhpNc
    ld ix,$4000                                                       ; 802e: dd 21 00... .!. A:fd BC:8099 DE:1000 HL:1234 IX:4000 IY:---- SP:---- szhpNc
    ld iyl,$20                                                        ; 8032: fd 2e 20    ..  A:fd BC:8099 DE:1000 HL:1234 IX:4000 IY:--20 SP:---- szhpNc
    inc ixh                                                           ; 8035: dd 24       .$  A:fd BC:8099 DE:1000 HL:1234 IX:4100 IY:--20 SP:---- szhpnc
    ld a,ixh                                                          ; 8037: dd 7c       .|  A:41 BC:8099 DE:1000 HL:1234 IX:4100 IY:--20 SP:---- szhpnc
    ld sp,$ff00                                                       ; 8039: 31 00 ff    1.. A:41 BC:8099 DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szhpnc
    push af                                                           ; 803c: f5          .   A:41 BC:8099 DE:1000 HL:1234 IX:4100 IY:--20 SP:fefe szhpnc
    pop bc                                                            ; 803d: c1          .   A:41 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szhpnc
    ld i,a                                                            ; 803e: ed 47       .G  A:41 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szhpnc
    ld a,i                                                            ; 8040: ed 57       .W  A:41 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szh-nc
    ld a,1                                                            ; 8042: 3e 01       >.  A:01 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szh-nc
    ex af,af'                                                         ; 8044: 08          .   A:-- BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 ------
    ld a,2                                                            ; 8045: 3e 02       >.  A:02 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 ------
    ex af,af'                                                         ; 8047: 08          .   A:01 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szh-nc
    exx                                                               ; 8048: d9          .   A:01 BC:---- DE:---- HL:---- IX:4100 IY:--20 SP:ff00 szh-nc
    ld b,3                                                            ; 8049: 06 03       ..  A:01 BC:03-- DE:---- HL:---- IX:4100 IY:--20 SP:ff00 szh-nc
    exx                                                               ; 804b: d9          .   A:01 BC:---- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szh-nc
    ld b,5                                                            ; 804c: 06 05       ..  A:01 BC:05-- DE:1000 HL:1234 IX:4100 IY:--20 SP:ff00 szh-nc
; $804e referenced 1 time by $804e
loop_c804e:
    djnz loop_c804e                                                   ; 804e: 10 fe       ..  A:-- BC:00-- DE:---- HL:---- IX:---- IY:---- SP:---- ------
    jr nz,return_1                                                    ; 8050: 20 0c        .  A:-- BC:00-- DE:---- HL:---- IX:---- IY:---- SP:---- -Z----
    jp c,return_1                                                     ; 8052: da 5e 80    .^. A:-- BC:00-- DE:---- HL:---- IX:---- IY:---- SP:---- -Z---c
    ret m                                                             ; 8055: f8          .   A:-- BC:00-- DE:---- HL:---- IX:---- IY:---- SP:---- sZ---c
    ldir                                                              ; 8056: ed b0       ..  A:-- BC:0000 DE:---- HL:---- IX:---- IY:---- SP:---- sZhpnc
    ld b,4                                                            ; 8058: 06 04       ..  A:-- BC:0400 DE:---- HL:---- IX:---- IY:---- SP:---- sZhpnc
    otir                                                              ; 805a: ed b3       ..  A:-- BC:0000 DE:---- HL:---- IX:---- IY:---- SP:---- sZ----
    in a,($fe)                                                        ; 805c: db fe       ..  A:-- BC:0000 DE:---- HL:---- IX:---- IY:---- SP:---- sZ----
; $805e referenced 2 times by $8050, $8052
return_1:
    ret                                                               ; 805e: c9          .   A:-- BC:---- DE:---- HL:---- IX:---- IY:---- SP:---- ------

pydis_end:


; Label references by decreasing frequency:
;     return_1:     2
;     loop_c804e:   1

; Automatically generated labels:
;     loop_c804e
;     return_1

; Stats:
;
;     Total size (Code + Data) = 95 bytes
;     Code                     = 95 bytes (100%)
;     Data                     = 0 bytes (0%)
;
;     Number of instructions   = 54
;     Number of data bytes     = 0 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 0 bytes
;     Number of strings        = 0

